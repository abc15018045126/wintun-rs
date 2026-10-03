use std::ffi::c_void;
use std::sync::Mutex as StdMutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_GEN_FAILURE, ERROR_OUTOFMEMORY, ERROR_PATH_NOT_FOUND,
    HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
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
use crate::types::{
    get_last_error, set_last_error, LocalFree, NamespaceMutex, OpenProcessToken, SafeHandle,
    WintunLoggerLevel, BOOL,
};

#[link(name = "kernel32")]
unsafe extern "system" {
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

struct BoundaryDescriptor(HANDLE);

impl BoundaryDescriptor {
    #[inline]
    fn new(h: HANDLE) -> Self {
        Self(h)
    }

    #[inline]
    fn as_mut_raw(&mut self) -> *mut HANDLE {
        &mut self.0
    }

    #[inline]
    fn raw(&self) -> HANDLE {
        self.0
    }

    #[inline]
    fn into_raw(mut self) -> HANDLE {
        let h = self.0;
        self.0 = std::ptr::null_mut();
        h
    }
}

impl Drop for BoundaryDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { DeleteBoundaryDescriptor(self.0) };
        }
    }
}

struct NamespaceState {
    private_namespace: HANDLE,
    boundary_descriptor: HANDLE,
}

unsafe impl Send for NamespaceState {}
unsafe impl Sync for NamespaceState {}

impl Drop for NamespaceState {
    fn drop(&mut self) {
        if !self.private_namespace.is_null() {
            unsafe {
                ClosePrivateNamespace(self.private_namespace, 0);
            }
        }
        if !self.boundary_descriptor.is_null() {
            unsafe {
                DeleteBoundaryDescriptor(self.boundary_descriptor);
            }
        }
    }
}

static SECURITY_CTX: StdMutex<Option<SecurityContext>> = StdMutex::new(None);
static NAMESPACE_STATE: StdMutex<Option<NamespaceState>> = StdMutex::new(None);

const MAX_SID_SIZE: usize = 68;

fn create_well_known_sid(
    sid_type: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> Option<[u8; MAX_SID_SIZE]> {
    let mut sid = [0u8; MAX_SID_SIZE];
    let mut size = sid.len() as u32;
    let ok = unsafe {
        CreateWellKnownSid(
            sid_type,
            std::ptr::null_mut(),
            sid.as_mut_ptr() as _,
            &mut size,
        )
    };
    if ok != 0 {
        Some(sid)
    } else {
        None
    }
}

fn check_is_local_system(local_system_sid: &[u8]) -> Option<bool> {
    let mut current_process_token = SafeHandle::null();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            current_process_token.as_mut_ptr(),
        )
    } == 0
    {
        return None;
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
            current_process_token.raw(),
            windows_sys::Win32::Security::TokenUser,
            token_user_buf.as_mut_ptr() as _,
            ret_bytes,
            &mut ret_bytes,
        )
    };

    if res != 0 {
        let token_user = unsafe { token_user_buf.assume_init() };
        Some(unsafe { EqualSid(token_user.user.User.Sid, local_system_sid.as_ptr() as _) != 0 })
    } else {
        None
    }
}

pub fn init_security_objects() -> bool {
    let mut ctx = SECURITY_CTX.lock().unwrap_or_else(|e| e.into_inner());
    if ctx.is_some() {
        return true;
    }

    let Some(local_system_sid) = create_well_known_sid(WinLocalSystemSid) else {
        return false;
    };

    let Some(is_local_system) = check_is_local_system(&local_system_sid) else {
        return false;
    };

    let wide_sddl = if is_local_system {
        windows_sys::w!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
    } else {
        windows_sys::w!("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
    };
    let mut sd: *mut c_void = std::ptr::null_mut();

    let conv = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl,
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
    let mut ctx = SECURITY_CTX.lock().unwrap_or_else(|e| e.into_inner());
    if ctx.is_none() {
        drop(ctx);
        if !init_security_objects() {
            return None;
        }
        ctx = SECURITY_CTX.lock().unwrap_or_else(|e| e.into_inner());
    }
    ctx.as_ref().map(|c| SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: c.security_descriptor,
        bInheritHandle: 0,
    })
}

pub fn namespace_runtime_init() -> bool {
    let mut state = NAMESPACE_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if state.is_some() {
        return true;
    }

    if !init_security_objects() {
        set_last_error(ERROR_GEN_FAILURE);
        return false;
    }

    let is_local_system = {
        let ctx = SECURITY_CTX.lock().unwrap_or_else(|e| e.into_inner());
        ctx.as_ref().is_some_and(|c| c.is_local_system)
    };

    let well_known_type = if is_local_system {
        WinLocalSystemSid
    } else {
        WinBuiltinAdministratorsSid
    };

    let Some(mut sid) = create_well_known_sid(well_known_type) else {
        log_last_error("Failed to create SID");
        return false;
    };

    let name_wintun = windows_sys::w!("Wintun");
    let boundary = unsafe { CreateBoundaryDescriptorW(name_wintun, 0) };
    if boundary.is_null() {
        log_last_error("Failed to create boundary descriptor");
        return false;
    }
    let mut boundary = BoundaryDescriptor::new(boundary);

    if unsafe { AddSIDToBoundaryDescriptor(boundary.as_mut_raw(), sid.as_mut_ptr() as _) } == 0 {
        log_last_error("Failed to add SID to boundary descriptor");
        return false;
    }

    let Some(sec_attr) = get_security_attributes() else {
        set_last_error(ERROR_OUTOFMEMORY);
        return false;
    };

    let mut p_ns: HANDLE;
    loop {
        p_ns = unsafe { CreatePrivateNamespaceW(&sec_attr, boundary.raw(), name_wintun) };
        if !p_ns.is_null() {
            break;
        }
        let mut last_err = get_last_error();
        if last_err == ERROR_ALREADY_EXISTS {
            p_ns = unsafe { OpenPrivateNamespaceW(boundary.raw(), name_wintun) };
            if !p_ns.is_null() {
                break;
            }
            last_err = get_last_error();
            if last_err == ERROR_PATH_NOT_FOUND {
                continue;
            }
            log_error(last_err, "Failed to open private namespace");
        } else {
            log_error(last_err, "Failed to create private namespace");
        }
        set_last_error(last_err);
        return false;
    }

    *state = Some(NamespaceState {
        private_namespace: p_ns,
        boundary_descriptor: boundary.into_raw(),
    });
    true
}

fn take_mutex(mutex_name: *const u16) -> Option<NamespaceMutex> {
    if !namespace_runtime_init() {
        return None;
    }
    let sec_attr = match get_security_attributes() {
        Some(sa) => sa,
        None => {
            set_last_error(ERROR_OUTOFMEMORY);
            return None;
        }
    };

    let mutex = unsafe { CreateMutexW(&sec_attr, 0, mutex_name) };
    if mutex.is_null() {
        log_last_error("Failed to create mutex");
        return None;
    }

    let result = unsafe { WaitForSingleObject(mutex, INFINITE) };
    match result {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Some(NamespaceMutex::new(mutex)),
        _ => {
            log_msg(
                WintunLoggerLevel::Err,
                &format!("Failed to get mutex (status: 0x{:x})", result),
            );
            unsafe {
                CloseHandle(mutex);
            }
            set_last_error(ERROR_GEN_FAILURE);
            None
        }
    }
}

pub fn namespace_take_driver_installation_mutex() -> Option<NamespaceMutex> {
    take_mutex(windows_sys::w!("Wintun\\Wintun-Driver-Installation-Mutex"))
}

pub fn namespace_take_device_installation_mutex() -> Option<NamespaceMutex> {
    take_mutex(windows_sys::w!("Wintun\\Wintun-Device-Installation-Mutex"))
}

pub fn namespace_done() {
    let mut state = NAMESPACE_STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.take();

    let mut ctx = SECURITY_CTX.lock().unwrap_or_else(|e| e.into_inner());
    ctx.take();
}
