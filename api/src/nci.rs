use std::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::core::GUID;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiGetClassDevsExW, SetupDiOpenDevRegKey, DICS_FLAG_GLOBAL, DIREG_DRV,
};
use windows_sys::Win32::Foundation::{
    FreeLibrary, ERROR_BUFFER_OVERFLOW, ERROR_DUP_NAME, ERROR_GEN_FAILURE, ERROR_NOT_FOUND,
    ERROR_SUCCESS, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
use windows_sys::Win32::System::Registry::HKEY;

use crate::logger::{log_error, log_last_error};
use crate::registry::registry_query_string;
use crate::types::*;

const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x00000800;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(lp_lib_file_name: *const u16, h_file: HANDLE, dw_flags: u32) -> HMODULE;
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
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

    let nci_module = unsafe {
        LoadLibraryExW(
            windows_sys::w!("nci.dll"),
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

fn convert_interface_alias_to_guid(wide_name: *const u16) -> Option<GUID> {
    let mut luid = NetLuid::default();
    let err = unsafe { ConvertInterfaceAliasToLuid(wide_name, &mut luid) };
    if err != 0 {
        let name_str = unsafe { from_wide_ptr(wide_name) };
        log_error(
            err,
            &format!(
                "Failed convert interface {} name to the locally unique identifier",
                name_str
            ),
        );
        set_last_error(err);
        return None;
    }
    let mut guid = GUID::from_u128(0);
    let err2 = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if err2 != 0 {
        let name_str = unsafe { from_wide_ptr(wide_name) };
        log_error(
            err2,
            &format!(
                "Failed to convert interface {} LUID ({}) to GUID",
                name_str, luid.value
            ),
        );
        set_last_error(err2);
        return None;
    }
    Some(guid)
}

fn rename_by_net_guid(guid: &GUID, wide_name: *const u16) -> bool {
    let mut last_error = ERROR_NOT_FOUND;
    let dev_info = DeviceInfoSet::new(unsafe {
        SetupDiGetClassDevsExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            windows_sys::w!("SWD\\Wintun"),
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    });
    if dev_info.is_invalid() {
        let err = get_last_error();
        set_last_error(err);
        return false;
    }

    for mut dev_info_data in enum_device_info(dev_info.raw()) {
        let key_raw = unsafe {
            SetupDiOpenDevRegKey(
                dev_info.raw(),
                &dev_info_data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DRV,
                windows_sys::Win32::System::Registry::KEY_QUERY_VALUE,
            )
        };
        if std::ptr::eq(key_raw, INVALID_HANDLE_VALUE as HKEY) || key_raw.is_null() {
            continue;
        }

        let key = RegKey::new(key_raw);
        let Ok(value_str) =
            registry_query_string(key_raw, windows_sys::w!("NetCfgInstanceId"), true)
        else {
            continue;
        };
        drop(key);
        let mut dev_guid = GUID::from_u128(0);
        if unsafe { CLSIDFromString(value_str.as_ptr(), &mut dev_guid) } < 0 {
            continue;
        }

        if guid_eq(&dev_guid, guid) {
            let name_len = (unsafe { wide_str_len(wide_name) } + 1) * 2;
            let set_ok = unsafe {
                SetupDiSetDevicePropertyW(
                    dev_info.raw(),
                    &mut dev_info_data,
                    &DEVPKEY_WINTUN_NAME,
                    DEVPROP_TYPE_STRING,
                    wide_name as *const u8,
                    name_len as u32,
                    0,
                )
            };
            last_error = if set_ok != 0 {
                ERROR_SUCCESS
            } else {
                get_last_error()
            };
            break;
        }
    }

    if last_error != ERROR_SUCCESS {
        set_last_error(last_error);
        false
    } else {
        true
    }
}

fn format_name_with_suffix(
    dst: &mut [u16; MAX_ADAPTER_NAME],
    base_name: *const u16,
    base_len: usize,
    suffix: u32,
) -> bool {
    let mut num_buf = [0u16; 10];
    let mut n = suffix;
    let mut num_len = 0;
    loop {
        num_buf[num_len] = (b'0' + (n % 10) as u8) as u16;
        num_len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    num_buf[..num_len].reverse();

    let total_len = base_len + 1 + num_len;
    if total_len >= MAX_ADAPTER_NAME {
        return false;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(base_name, dst.as_mut_ptr(), base_len);
    }
    dst[base_len] = b' ' as u16;
    dst[base_len + 1..base_len + 1 + num_len].copy_from_slice(&num_buf[..num_len]);
    dst[total_len] = 0;
    true
}

pub fn nci_set_adapter_name(guid: &GUID, wide_name: *const u16) -> Result<(), u32> {
    let set_conn_name = match load_nci_function() {
        Some(f) => f,
        None => {
            set_last_error(ERROR_GEN_FAILURE);
            return Err(ERROR_GEN_FAILURE);
        }
    };

    let base_len = unsafe {
        let mut len = 0;
        while *wide_name.add(len) != 0 {
            len += 1;
            if len >= MAX_ADAPTER_NAME {
                set_last_error(ERROR_BUFFER_OVERFLOW);
                return Err(ERROR_BUFFER_OVERFLOW);
            }
        }
        len
    };

    let max_suffix = 1000;
    let mut available_name = [0u16; MAX_ADAPTER_NAME];
    unsafe {
        std::ptr::copy_nonoverlapping(wide_name, available_name.as_mut_ptr(), base_len + 1);
    }

    for i in 0.. {
        let mut last_error = unsafe { set_conn_name(guid, available_name.as_ptr()) };

        if last_error == ERROR_DUP_NAME {
            if let Some(guid2) = convert_interface_alias_to_guid(available_name.as_ptr()) {
                for j in 0..max_suffix {
                    let mut proposal = [0u16; MAX_ADAPTER_NAME];
                    if !format_name_with_suffix(&mut proposal, wide_name, base_len, (j + 1) as u32)
                    {
                        set_last_error(ERROR_BUFFER_OVERFLOW);
                        return Err(ERROR_BUFFER_OVERFLOW);
                    }
                    if unsafe { wide_eq_ignore_case(proposal.as_ptr(), available_name.as_ptr()) } {
                        continue;
                    }
                    let last_error2 = unsafe { set_conn_name(&guid2, proposal.as_ptr()) };
                    if last_error2 == ERROR_DUP_NAME {
                        continue;
                    }
                    if !rename_by_net_guid(&guid2, proposal.as_ptr()) {
                        let prop_str = unsafe { from_wide_ptr(proposal.as_ptr()) };
                        log_last_error(&format!(
                            "Failed to set foreign adapter name to \"{}\"",
                            prop_str
                        ));
                    }
                    if last_error2 == ERROR_SUCCESS {
                        last_error = unsafe { set_conn_name(guid, available_name.as_ptr()) };
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
            set_last_error(last_error);
            return Err(last_error);
        }

        if !format_name_with_suffix(&mut available_name, wide_name, base_len, (i + 1) as u32) {
            set_last_error(ERROR_BUFFER_OVERFLOW);
            return Err(ERROR_BUFFER_OVERFLOW);
        }
    }

    set_last_error(ERROR_DUP_NAME);
    Err(ERROR_DUP_NAME)
}
