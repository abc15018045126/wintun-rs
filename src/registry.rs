// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.

use windows_sys::Win32::Foundation::{ERROR_DATATYPE_MISMATCH, ERROR_GEN_FAILURE, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{RegQueryValueExW, REG_DWORD, REG_EXPAND_SZ, REG_SZ};

use crate::logger::{get_registry_key_path, log_error, log_msg};
use crate::types::{from_wide_null, to_wide, ExpandEnvironmentStringsW, WintunLoggerLevel, HKEY};

fn val_name_ptr(name: Option<&str>) -> (Option<Vec<u16>>, *const u16) {
    let w = name.map(to_wide);
    let ptr = w.as_deref().map_or(std::ptr::null(), |v| v.as_ptr());
    (w, ptr)
}

pub fn registry_query_string(
    key: HKEY,
    value_name: Option<&str>,
    allow_expand: bool,
) -> Result<String, u32> {
    let (_wide_val_name, val_ptr) = val_name_ptr(value_name);

    let mut val_type: u32 = 0;
    let mut bytes_len: u32 = 0;

    let res = unsafe {
        RegQueryValueExW(
            key,
            val_ptr,
            std::ptr::null_mut(),
            &mut val_type,
            std::ptr::null_mut(),
            &mut bytes_len,
        )
    };

    if res != ERROR_SUCCESS {
        let key_path = get_registry_key_path(key);
        log_error(
            res,
            &format!(
                "Failed to query registry value size {}\\{}",
                key_path,
                value_name.unwrap_or("<default>")
            ),
        );
        return Err(res);
    }

    if val_type != REG_SZ && (!allow_expand || val_type != REG_EXPAND_SZ) {
        let key_path = get_registry_key_path(key);
        log_msg(
            WintunLoggerLevel::Err,
            &format!(
                "Registry value {}\\{} is not a string (type: {})",
                key_path,
                value_name.unwrap_or("<default>"),
                val_type
            ),
        );
        return Err(ERROR_DATATYPE_MISMATCH);
    }

    if bytes_len == 0 {
        return Ok(String::new());
    }

    let mut buf = vec![0u8; bytes_len as usize + 2];
    let res = unsafe {
        RegQueryValueExW(
            key,
            val_ptr,
            std::ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr(),
            &mut bytes_len,
        )
    };

    if res != ERROR_SUCCESS {
        let key_path = get_registry_key_path(key);
        log_error(
            res,
            &format!(
                "Failed to read registry value {}\\{}",
                key_path,
                value_name.unwrap_or("<default>")
            ),
        );
        return Err(res);
    }

    let u16_len = bytes_len as usize / std::mem::size_of::<u16>();
    let u16_slice = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u16, u16_len) };
    let raw_str = from_wide_null(u16_slice);

    if val_type == REG_EXPAND_SZ {
        let wide_raw = to_wide(&raw_str);
        let len = unsafe { ExpandEnvironmentStringsW(wide_raw.as_ptr(), std::ptr::null_mut(), 0) };
        let mut expanded_buf = vec![0u16; len as usize];
        if len == 0
            || unsafe {
                ExpandEnvironmentStringsW(wide_raw.as_ptr(), expanded_buf.as_mut_ptr(), len)
            } == 0
        {
            log_msg(
                WintunLoggerLevel::Err,
                "Failed to expand environment strings",
            );
            return Err(ERROR_GEN_FAILURE);
        }

        Ok(from_wide_null(&expanded_buf))
    } else {
        Ok(raw_str)
    }
}

pub fn registry_query_dword(
    key: HKEY,
    value_name: Option<&str>,
    must_exist: bool,
) -> Result<u32, u32> {
    let (_wide_val_name, val_ptr) = val_name_ptr(value_name);

    let mut val_type: u32 = 0;
    let mut val: u32 = 0;
    let mut bytes_len: u32 = std::mem::size_of::<u32>() as u32;

    let res = unsafe {
        RegQueryValueExW(
            key,
            val_ptr,
            std::ptr::null_mut(),
            &mut val_type,
            &mut val as *mut u32 as *mut u8,
            &mut bytes_len,
        )
    };

    if res != ERROR_SUCCESS {
        if must_exist {
            let key_path = get_registry_key_path(key);
            log_error(
                res,
                &format!(
                    "Failed to read registry value {}\\{}",
                    key_path,
                    value_name.unwrap_or("<default>")
                ),
            );
        }
        return Err(res);
    }

    if val_type != REG_DWORD {
        let key_path = get_registry_key_path(key);
        log_msg(
            WintunLoggerLevel::Err,
            &format!(
                "Registry value {}\\{} is not a DWORD (type: {})",
                key_path,
                value_name.unwrap_or("<default>"),
                val_type
            ),
        );
        return Err(ERROR_DATATYPE_MISMATCH);
    }

    Ok(val)
}
