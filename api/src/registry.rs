use windows_sys::Win32::Foundation::{ERROR_INVALID_DATA, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegQueryValueExW, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ,
};

use crate::logger::{get_registry_key_path, is_logger_active, log_error, log_last_error, log_msg};
use crate::types::{
    from_wide_ptr, set_last_error, ExpandEnvironmentStringsW, WintunLoggerLevel,
    ERROR_INVALID_DATATYPE, HKEY,
};

pub fn registry_get_string(buf: &mut Vec<u16>, value_type: u32) -> Result<(), u32> {
    if !buf.contains(&0) {
        buf.push(0);
    }

    if value_type != REG_EXPAND_SZ {
        return Ok(());
    }

    if buf.is_empty() || buf[0] == 0 {
        return Ok(());
    }

    let mut len = buf.len() as u32;
    loop {
        let mut expanded = vec![0u16; len as usize];
        let result = unsafe { ExpandEnvironmentStringsW(buf.as_ptr(), expanded.as_mut_ptr(), len) };
        if result == 0 {
            let buf_str = unsafe { from_wide_ptr(buf.as_ptr()) };
            let err = log_last_error(&format!(
                "Failed to expand environment variables: {}",
                buf_str
            ));
            set_last_error(err);
            return Err(err);
        }
        if result > len {
            len = result;
            continue;
        }
        *buf = expanded;
        return Ok(());
    }
}

pub fn registry_query_string(
    key: HKEY,
    value_name: *const u16,
    log: bool,
) -> Result<Vec<u16>, u32> {
    let mut val_type: u32 = 0;
    let mut bytes_len: u32 = 512; // 256 WCHARs initial buffer, matching C's 256 * sizeof(WCHAR)
    let mut buf: Vec<u16> = vec![0u16; 256];

    loop {
        let res = unsafe {
            RegQueryValueExW(
                key,
                value_name,
                std::ptr::null_mut(),
                &mut val_type,
                buf.as_mut_ptr() as *mut u8,
                &mut bytes_len,
            )
        };

        if res == ERROR_SUCCESS {
            let chars_len = (bytes_len as usize) / 2;
            buf.truncate(chars_len);
            break;
        }

        if res != ERROR_MORE_DATA {
            if log && is_logger_active() {
                let key_path = get_registry_key_path(key);
                let name_str = if value_name.is_null() {
                    "<default>".to_string()
                } else {
                    unsafe { from_wide_ptr(value_name) }
                };
                log_error(
                    res,
                    &format!("Failed to query registry value {}\\{}", key_path, name_str),
                );
            }
            set_last_error(res);
            return Err(res);
        }

        let u16_len = (bytes_len as usize).div_ceil(2) + 1;
        buf.resize(u16_len, 0);
    }

    match val_type {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
            registry_get_string(&mut buf, val_type)?;
            Ok(buf)
        }
        _ => {
            if log && is_logger_active() {
                let key_path = get_registry_key_path(key);
                let name_str = if value_name.is_null() {
                    "<default>".to_string()
                } else {
                    unsafe { from_wide_ptr(value_name) }
                };
                log_msg(
                    WintunLoggerLevel::Err,
                    &format!(
                        "Registry value {}\\{} is not a string (type: {})",
                        key_path, name_str, val_type
                    ),
                );
            }
            set_last_error(ERROR_INVALID_DATATYPE);
            Err(ERROR_INVALID_DATATYPE)
        }
    }
}

pub fn registry_query_dword(key: HKEY, value_name: *const u16, log: bool) -> Result<u32, u32> {
    let mut val_type: u32 = 0;
    let mut val: u32 = 0;
    let mut bytes_len: u32 = std::mem::size_of::<u32>() as u32;

    let res = unsafe {
        RegQueryValueExW(
            key,
            value_name,
            std::ptr::null_mut(),
            &mut val_type,
            &mut val as *mut u32 as *mut u8,
            &mut bytes_len,
        )
    };

    if res != ERROR_SUCCESS {
        if log && is_logger_active() {
            let key_path = get_registry_key_path(key);
            let name_str = if value_name.is_null() {
                "<default>".to_string()
            } else {
                unsafe { from_wide_ptr(value_name) }
            };
            log_error(
                res,
                &format!("Failed to query registry value {}\\{}", key_path, name_str),
            );
        }
        set_last_error(res);
        return Err(res);
    }

    if val_type != REG_DWORD {
        if log && is_logger_active() {
            let key_path = get_registry_key_path(key);
            let name_str = if value_name.is_null() {
                "<default>".to_string()
            } else {
                unsafe { from_wide_ptr(value_name) }
            };
            log_msg(
                WintunLoggerLevel::Err,
                &format!(
                    "Value {}\\{} is not a DWORD (type: {})",
                    key_path, name_str, val_type
                ),
            );
        }
        set_last_error(ERROR_INVALID_DATATYPE);
        return Err(ERROR_INVALID_DATATYPE);
    }

    if bytes_len != std::mem::size_of::<u32>() as u32 {
        if log && is_logger_active() {
            let key_path = get_registry_key_path(key);
            let name_str = if value_name.is_null() {
                "<default>".to_string()
            } else {
                unsafe { from_wide_ptr(value_name) }
            };
            log_msg(
                WintunLoggerLevel::Err,
                &format!(
                    "Value {}\\{} size is not 4 bytes (size: {})",
                    key_path, name_str, bytes_len
                ),
            );
        }
        set_last_error(ERROR_INVALID_DATA);
        return Err(ERROR_INVALID_DATA);
    }

    Ok(val)
}

impl crate::types::RegKey {
    pub fn query_string(&self, value_name: *const u16, log: bool) -> Result<Vec<u16>, u32> {
        registry_query_string(self.0, value_name, log)
    }

    pub fn query_dword(&self, value_name: *const u16, log: bool) -> Result<u32, u32> {
        registry_query_dword(self.0, value_name, log)
    }
}
