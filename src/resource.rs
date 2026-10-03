// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.

use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{SetLastError, ERROR_GEN_FAILURE, ERROR_WRITE_FAULT};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, WriteFile, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_TEMPORARY,
};

use crate::logger::{log_last_error, log_msg};
use crate::namespace::get_security_attributes;
use crate::ntdll::RtlGenRandom;
use crate::types::{to_wide, GetWindowsDirectoryW, SafeHandle, WintunLoggerLevel};

pub const DRIVER_CAT: &[u8] = include_bytes!("../../Release/amd64/driver/wintun.cat");
pub const DRIVER_INF: &[u8] = include_bytes!("../../Release/amd64/driver/wintun.inf");
pub const DRIVER_SYS: &[u8] = include_bytes!("../../Release/amd64/driver/wintun.sys");

const GENERIC_WRITE: u32 = 0x40000000;

pub fn resource_create_temporary_directory() -> Result<PathBuf, u32> {
    let mut win_dir = [0u16; 260];
    let len = unsafe { GetWindowsDirectoryW(win_dir.as_mut_ptr(), win_dir.len() as u32) };
    if len == 0 {
        return Err(log_last_error("Failed to get Windows folder"));
    }

    let win_dir_str = String::from_utf16_lossy(&win_dir[..len as usize]);
    let temp_base = Path::new(&win_dir_str).join("Temp");

    let mut random_bytes = [0u8; 32];
    if unsafe { RtlGenRandom(random_bytes.as_mut_ptr() as _, random_bytes.len() as u32) } == 0 {
        log_msg(WintunLoggerLevel::Err, "Failed to generate random");
        unsafe { SetLastError(ERROR_GEN_FAILURE) };
        return Err(ERROR_GEN_FAILURE);
    }

    let hex_dir: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let temp_sub_dir = temp_base.join(hex_dir);

    let wide_path = to_wide(&temp_sub_dir.to_string_lossy());

    let Some(sec_attr) = get_security_attributes() else {
        unsafe { SetLastError(ERROR_GEN_FAILURE) };
        return Err(ERROR_GEN_FAILURE);
    };

    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &sec_attr) } == 0 {
        return Err(log_last_error(&format!(
            "Failed to create temporary folder {}",
            temp_sub_dir.display()
        )));
    }

    Ok(temp_sub_dir)
}

pub fn resource_copy_to_file(destination_path: &Path, content: &[u8]) -> Result<(), u32> {
    let wide_dest = to_wide(&destination_path.to_string_lossy());

    let Some(sec_attr) = get_security_attributes() else {
        unsafe { SetLastError(ERROR_GEN_FAILURE) };
        return Err(ERROR_GEN_FAILURE);
    };

    let handle_raw = unsafe {
        CreateFileW(
            wide_dest.as_ptr(),
            GENERIC_WRITE,
            0,
            &sec_attr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
            std::ptr::null_mut(),
        )
    };

    let handle = SafeHandle::new(handle_raw);
    if handle.is_invalid() {
        return Err(log_last_error(&format!(
            "Failed to create file {}",
            destination_path.display()
        )));
    }

    let mut bytes_written: u32 = 0;
    let write_res = unsafe {
        WriteFile(
            handle.raw(),
            content.as_ptr(),
            content.len() as u32,
            &mut bytes_written,
            std::ptr::null_mut(),
        )
    };

    if write_res == 0 {
        return Err(log_last_error(&format!(
            "Failed to write file {}",
            destination_path.display()
        )));
    }

    if bytes_written != content.len() as u32 {
        log_msg(
            WintunLoggerLevel::Err,
            &format!(
                "Incomplete write to {} (written: {}, expected: {})",
                destination_path.display(),
                bytes_written,
                content.len()
            ),
        );
        unsafe { SetLastError(ERROR_WRITE_FAULT) };
        return Err(ERROR_WRITE_FAULT);
    }

    Ok(())
}
