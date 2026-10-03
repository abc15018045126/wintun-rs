// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.

use std::ffi::c_void;
use std::sync::Mutex as StdMutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_ALREADY_EXISTS, ERROR_GEN_FAILURE,
    ERROR_OUTOFMEMORY, ERROR_PATH_NOT_FOUND, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, WinBuiltinAdministratorsSid,
    WinLocalSystemSid, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    CreateBoundaryDescriptorW, CreateMutexW, CreatePrivateNamespaceW, GetCurrentProcess,
    OpenPrivateNamespaceW, WaitForSingleObject, INFINITE,
};

use crate::logger::{log_error, log_last_error, log_msg};
use crate::types::{to_wide, LocalFree, OpenProcessToken, ReleaseMutex, WintunLoggerLevel, BOOL};

#[link(name = "kernel32")]
extern "system" {
    fn AddSIDToBoundaryDescriptor(
        boundary_descriptor: *mut HANDLE,
        required_sid: *mut c_void,
    ) -> BOOL;
    fn DeleteBoundaryDescriptor(boundary_descriptor: HANDLE);
    fn ClosePrivateNamespace(handle: HANDLE, flags: u32) -> u8;
}

pub struct SecurityContext {
    pub is_local_system: bool,
    pub security_descriptor: *mut c_void,
}

unsafe impl Send for SecurityContext {}
unsafe impl Sync for SecurityContext {}

impl Drop for SecurityContext {
    fn drop(&mut self) {
        if !self.security_descriptor.is_null() {
            unsafe {
                LocalFree(self.security_descriptor);
            }
        }
    }
}

struct NamespaceState {
    private_namespace: HANDLE,
    boundary_descriptor: HANDLE,
}

unsafe impl Send for NamespaceState {}
unsafe impl Sync for NamespaceState {}

static SECURITY_CTX: StdMutex<Option<SecurityContext>> = StdMutex::new(None);
static NAMESPACE_STATE: StdMutex<Option<NamespaceState>> = StdMutex::new(None);

pub fn init_security_objects() -> bool {
    let mut ctx = SECURITY_CTX.lock().unwrap();
    if ctx.is_some() {
        return true;
    }

    const MAX_SID_SIZE: usize = 68;
    let mut local_system_sid = [0u8; MAX_SID_SIZE];
    let mut required_bytes: u32 = local_system_sid.len() as u32;

    let success = unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            local_system_sid.as_mut_ptr() as _,
            &mut required_bytes,
        )
    };
    if success == 0 {
        return false;
    }

    let mut current_process_token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut current_process_token) }
        == 0
    {
        return false;
    }

    #[repr(C)]
    struct TokenUserBuf {
        user: TOKEN_USER,
        extra: [u8; MAX_SID_SIZE],
    }

    let mut token_user_buf = std::mem::MaybeUninit::<TokenUserBuf>::uninit();
    let mut ret_bytes: u32 = std::mem::size_of::<TokenUserBuf>() as u32;

    let res = unsafe {
        GetTokenInformation(
            current_process_token,
            windows_sys::Win32::Security::TokenUser,
            token_user_buf.as_mut_ptr() as _,
            ret_bytes,
            &mut ret_bytes,
        )
    };

    let is_local_system = if res != 0 {
        let token_user = unsafe { token_user_buf.assume_init() };
        unsafe { EqualSid(token_user.user.User.Sid, local_system_sid.as_mut_ptr() as _) != 0 }
    } else {
        false
    };

    unsafe {
        CloseHandle(current_process_token);
    }

    let sddl = if is_local_system {
        "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)"
    } else {
        "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)"
    };
    let wide_sddl = to_wide(sddl);
    let mut sd: *mut c_void = std::ptr::null_mut();

    let conv = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            1, // SDDL_REVISION_1
            &mut sd,
            std::ptr::null_mut(),
        )
    };

    if conv == 0 {
        return false;
    }

    *ctx = Some(SecurityContext {
        is_local_system,
        security_descriptor: sd,
    });
    true
}

pub fn get_security_attributes() -> Option<SECURITY_ATTRIBUTES> {
    init_security_objects();
    let ctx = SECURITY_CTX.lock().unwrap();
    ctx.as_ref().map(|c| SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: c.security_descriptor,
        bInheritHandle: 0,
    })
}

pub fn namespace_runtime_init() -> bool {
    let mut state = NAMESPACE_STATE.lock().unwrap();
    if state.is_some() {
        return true;
    }

    if !init_security_objects() {
        unsafe { SetLastError(ERROR_GEN_FAILURE) };
        return false;
    }

    let is_local_system = {
        let ctx = SECURITY_CTX.lock().unwrap();
        ctx.as_ref().is_some_and(|c| c.is_local_system)
    };

    const MAX_SID_SIZE: usize = 68;
    let mut sid = [0u8; MAX_SID_SIZE];
    let mut sid_size: u32 = sid.len() as u32;

    let well_known_type = if is_local_system {
        WinLocalSystemSid
    } else {
        WinBuiltinAdministratorsSid
    };

    if unsafe {
        CreateWellKnownSid(
            well_known_type,
            std::ptr::null_mut(),
            sid.as_mut_ptr() as _,
            &mut sid_size,
        )
    } == 0
    {
        log_last_error("Failed to create SID");
        return false;
    }

    let name_wintun = to_wide("Wintun");
    let mut boundary = unsafe { CreateBoundaryDescriptorW(name_wintun.as_ptr(), 0) };
    if boundary.is_null() {
        log_last_error("Failed to create boundary descriptor");
        return false;
    }

    if unsafe { AddSIDToBoundaryDescriptor(&mut boundary, sid.as_mut_ptr() as _) } == 0 {
        log_last_error("Failed to add SID to boundary descriptor");
        unsafe { DeleteBoundaryDescriptor(boundary) };
        return false;
    }

    let Some(sec_attr) = get_security_attributes() else {
        unsafe {
            DeleteBoundaryDescriptor(boundary);
            SetLastError(ERROR_OUTOFMEMORY);
        }
        return false;
    };

    let mut p_ns: HANDLE;
    loop {
        p_ns = unsafe { CreatePrivateNamespaceW(&sec_attr, boundary, name_wintun.as_ptr()) };
        if !p_ns.is_null() {
            break;
        }
        let last_err = unsafe { GetLastError() };
        if last_err == ERROR_ALREADY_EXISTS {
            p_ns = unsafe { OpenPrivateNamespaceW(boundary, name_wintun.as_ptr()) };
            if !p_ns.is_null() {
                break;
            }
            if unsafe { GetLastError() } == ERROR_PATH_NOT_FOUND {
                continue;
            }
            log_error(
                unsafe { GetLastError() },
                "Failed to open private namespace",
            );
        } else {
            log_error(last_err, "Failed to create private namespace");
        }
        unsafe {
            DeleteBoundaryDescriptor(boundary);
            SetLastError(last_err);
        }
        return false;
    }

    *state = Some(NamespaceState {
        private_namespace: p_ns,
        boundary_descriptor: boundary,
    });
    true
}

fn take_mutex(mutex_name_suffix: &str) -> Option<HANDLE> {
    if !namespace_runtime_init() {
        return None;
    }
    let Some(sec_attr) = get_security_attributes() else {
        unsafe { SetLastError(ERROR_OUTOFMEMORY) };
        return None;
    };

    let wide_name = to_wide(&format!("Wintun\\{}", mutex_name_suffix));

    let mutex = unsafe { CreateMutexW(&sec_attr, 0, wide_name.as_ptr()) };
    if mutex.is_null() {
        log_last_error("Failed to create mutex");
        return None;
    }

    let result = unsafe { WaitForSingleObject(mutex, INFINITE) };
    match result {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Some(mutex),
        _ => {
            log_msg(
                WintunLoggerLevel::Err,
                &format!("Failed to get mutex (status: 0x{:x})", result),
            );
            unsafe {
                CloseHandle(mutex);
                SetLastError(ERROR_GEN_FAILURE);
            }
            None
        }
    }
}

pub fn namespace_take_driver_installation_mutex() -> Option<HANDLE> {
    take_mutex("Wintun-Driver-Installation-Mutex")
}

pub fn namespace_take_device_installation_mutex() -> Option<HANDLE> {
    take_mutex("Wintun-Device-Installation-Mutex")
}

pub fn namespace_release_mutex(mutex: HANDLE) {
    if !mutex.is_null() {
        unsafe {
            ReleaseMutex(mutex);
            CloseHandle(mutex);
        }
    }
}

pub fn namespace_done() {
    let mut state = NAMESPACE_STATE.lock().unwrap();
    if let Some(s) = state.take() {
        if !s.private_namespace.is_null() {
            unsafe {
                ClosePrivateNamespace(s.private_namespace, 0);
                DeleteBoundaryDescriptor(s.boundary_descriptor);
            }
        }
    }

    let mut ctx = SECURITY_CTX.lock().unwrap();
    ctx.take();
}
