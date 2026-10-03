// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.

use std::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::core::GUID;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiGetClassDevsExW, SetupDiOpenDevRegKey, DICS_FLAG_GLOBAL,
    DIREG_DRV,
};
use windows_sys::Win32::Foundation::{
    FreeLibrary, SetLastError, ERROR_DUP_NAME, ERROR_GEN_FAILURE, ERROR_SUCCESS, HANDLE, HMODULE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
use windows_sys::Win32::System::Registry::{RegCloseKey, HKEY};

use crate::logger::{log_error, log_last_error};
use crate::registry::registry_query_string;
use crate::types::*;

const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x00000800;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(lp_lib_file_name: *const u16, h_file: HANDLE, dw_flags: u32) -> HMODULE;
}

#[link(name = "iphlpapi")]
extern "system" {
    fn ConvertInterfaceAliasToLuid(
        interface_alias: *const u16,
        interface_luid: *mut NetLuid,
    ) -> u32;

    fn ConvertInterfaceLuidToGuid(interface_luid: *const NetLuid, interface_guid: *mut GUID)
        -> u32;
}

type NciSetConnectionNameFn =
    unsafe extern "system" fn(guid: *const GUID, new_name: *const u16) -> u32;

static NCI_SET_CONNECTION_NAME: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

fn load_nci_function() -> Option<NciSetConnectionNameFn> {
    let existing = NCI_SET_CONNECTION_NAME.load(Ordering::SeqCst);
    if !existing.is_null() {
        return Some(unsafe { std::mem::transmute::<*mut (), NciSetConnectionNameFn>(existing) });
    }

    let nci_name = to_wide("nci.dll");
    let nci_module = unsafe {
        LoadLibraryExW(
            nci_name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };

    if nci_module.is_null() {
        log_last_error("Failed to load nci.dll");
        return None;
    }

    let proc_name = b"NciSetConnectionName\0";
    let proc_addr = unsafe { GetProcAddress(nci_module, proc_name.as_ptr()) };

    if let Some(func) = proc_addr {
        NCI_SET_CONNECTION_NAME.store(func as *mut (), Ordering::SeqCst);
        Some(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, NciSetConnectionNameFn>(
                func,
            )
        })
    } else {
        log_last_error("Failed to find NciSetConnectionName in nci.dll");
        unsafe {
            FreeLibrary(nci_module);
        }
        None
    }
}

fn convert_interface_alias_to_guid(name: &str) -> Option<GUID> {
    let wide_name = to_wide(name);
    let mut luid = NetLuid::default();
    let err = unsafe { ConvertInterfaceAliasToLuid(wide_name.as_ptr(), &mut luid) };
    if err != 0 {
        log_error(
            err,
            &format!("Failed to convert interface {} name to LUID", name),
        );
        unsafe { SetLastError(err) };
        return None;
    }
    let mut guid: GUID = unsafe { std::mem::zeroed() };
    let err2 = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if err2 != 0 {
        log_error(
            err2,
            &format!("Failed to convert interface {} LUID to GUID", name),
        );
        unsafe { SetLastError(err2) };
        return None;
    }
    Some(guid)
}

fn rename_by_net_guid(guid: &GUID, name: &str) -> bool {
    let wintun_enum = to_wide("SWD\\Wintun");
    let dev_info = unsafe {
        SetupDiGetClassDevsExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            wintun_enum.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if dev_info == INVALID_HDEVINFO || dev_info == 0 {
        return false;
    }

    for mut dev_info_data in enum_device_info(dev_info) {
        let key = unsafe {
            SetupDiOpenDevRegKey(
                dev_info,
                &dev_info_data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DRV,
                windows_sys::Win32::System::Registry::KEY_QUERY_VALUE,
            )
        };
        if std::ptr::eq(key, INVALID_HANDLE_VALUE as HKEY) || key.is_null() {
            continue;
        }

        let val_str = registry_query_string(key, Some("NetCfgInstanceId"), false);
        unsafe { RegCloseKey(key) };

        let Ok(val_str) = val_str else {
            continue;
        };

        let wide_guid = to_wide(&val_str);
        let mut dev_guid: GUID = unsafe { std::mem::zeroed() };
        let hr = unsafe { CLSIDFromString(wide_guid.as_ptr(), &mut dev_guid) };
        if hr < 0 {
            continue;
        }

        if guid_eq(&dev_guid, guid) {
            let wide_name = to_wide(name);
            let set_ok = unsafe {
                SetupDiSetDevicePropertyW(
                    dev_info,
                    &mut dev_info_data,
                    &DEVPKEY_WINTUN_NAME,
                    DEVPROP_TYPE_STRING,
                    wide_name.as_ptr() as *const u8,
                    (wide_name.len() * 2) as u32,
                    0,
                )
            };
            unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
            return set_ok != 0;
        }
    }

    unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
    false
}

pub fn nci_set_adapter_name(guid: &GUID, name: &str) -> Result<(), u32> {
    let set_conn_name = match load_nci_function() {
        Some(f) => f,
        None => {
            unsafe {
                SetLastError(ERROR_GEN_FAILURE);
            }
            return Err(ERROR_GEN_FAILURE);
        }
    };

    let max_suffix = 1000;
    let mut available_name = name.to_string();

    for i in 0..=max_suffix {
        let wide_available = to_wide(&available_name);
        let mut last_error = unsafe { set_conn_name(guid, wide_available.as_ptr()) };

        if last_error == ERROR_DUP_NAME {
            if let Some(guid2) = convert_interface_alias_to_guid(&available_name) {
                for j in 0..max_suffix {
                    let proposal = format!("{} {}", name, j + 1);
                    if proposal.eq_ignore_ascii_case(&available_name) {
                        continue;
                    }
                    let wide_proposal = to_wide(&proposal);
                    let last_error2 = unsafe { set_conn_name(&guid2, wide_proposal.as_ptr()) };
                    if last_error2 == ERROR_DUP_NAME {
                        continue;
                    }
                    if !rename_by_net_guid(&guid2, &proposal) {
                        log_last_error(&format!(
                            "Failed to set foreign adapter name to \"{}\"",
                            proposal
                        ));
                    }
                    if last_error2 == ERROR_SUCCESS {
                        last_error = unsafe { set_conn_name(guid, wide_available.as_ptr()) };
                        if last_error == ERROR_SUCCESS {
                            break;
                        }
                    }
                    break;
                }
            }
        }

        if last_error == ERROR_SUCCESS {
            return Ok(());
        }

        if i >= max_suffix || last_error != ERROR_DUP_NAME {
            log_error(
                last_error,
                &format!("Failed to set adapter name to \"{}\"", available_name),
            );
            unsafe { SetLastError(last_error) };
            return Err(last_error);
        }

        available_name = format!("{} {}", name, i + 1);
    }

    log_error(
        ERROR_DUP_NAME,
        &format!(
            "Failed to find unique name for adapter starting with \"{}\"",
            name
        ),
    );
    unsafe {
        SetLastError(ERROR_DUP_NAME);
    }
    Err(ERROR_DUP_NAME)
}
