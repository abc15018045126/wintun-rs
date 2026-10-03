// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.

use std::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::{FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM};

use crate::ntdll::{NtQueryKey, NtQuerySystemTime};
use crate::types::{
    from_wide_null, to_wide, WintunLoggerCallback, WintunLoggerLevel,
    FORMAT_MESSAGE_MAX_WIDTH_MASK, HKEY, MAX_REG_PATH,
};

const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

unsafe extern "system" fn nop_logger(
    _level: WintunLoggerLevel,
    _timestamp: u64,
    _message: *const u16,
) {
}

static LOGGER_CALLBACK: AtomicPtr<()> = AtomicPtr::new(nop_logger as *mut ());

pub fn now() -> u64 {
    let mut timestamp: i64 = 0;
    unsafe {
        NtQuerySystemTime(&mut timestamp);
    }
    timestamp as u64
}

pub fn set_logger(new_logger: Option<WintunLoggerCallback>) {
    let func = match new_logger {
        Some(f) => f as *mut (),
        None => nop_logger as *mut (),
    };
    LOGGER_CALLBACK.store(func, Ordering::SeqCst);
}

pub fn get_logger() -> WintunLoggerCallback {
    let ptr = LOGGER_CALLBACK.load(Ordering::SeqCst);
    unsafe { std::mem::transmute::<*mut (), WintunLoggerCallback>(ptr) }
}

pub fn log_msg(level: WintunLoggerLevel, message: &str) -> u32 {
    let last_error = unsafe { GetLastError() };
    let wide_msg = to_wide(message);
    let logger = get_logger();
    unsafe {
        logger(level, now(), wide_msg.as_ptr());
        SetLastError(last_error);
    }
    last_error
}

pub fn log_error(error: u32, prefix: &str) -> u32 {
    let hr = if (error & 0xFFFF0000) == 0xE0000000 {
        error
    } else {
        (error & 0x0000FFFF) | 0x80070000
    };

    let mut system_message = [0u16; 512];
    let format_msg = |code: u32, buf: &mut [u16]| -> u32 {
        unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS
                    | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                std::ptr::null(),
                code,
                0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                std::ptr::null(),
            )
        }
    };

    let mut len = format_msg(error, &mut system_message);
    if len == 0 {
        len = format_msg(hr, &mut system_message);
    }

    let full_msg = if len > 0 {
        let sys_str = from_wide_null(&system_message[..len as usize]);
        format!("{}: {}(Code 0x{:08X})", prefix, sys_str.trim(), error)
    } else {
        format!("{}: Code 0x{:08X}", prefix, error)
    };

    let wide_msg = to_wide(&full_msg);
    let logger = get_logger();
    unsafe {
        logger(WintunLoggerLevel::Err, now(), wide_msg.as_ptr());
    }
    error
}

pub fn log_last_error(prefix: &str) -> u32 {
    let last_error = unsafe { GetLastError() };
    log_error(last_error, prefix);
    unsafe {
        SetLastError(last_error);
    }
    last_error
}

pub fn get_registry_key_path(key: HKEY) -> String {
    let last_error = unsafe { GetLastError() };
    if key.is_null() {
        return "<null>".to_string();
    }

    #[repr(C)]
    struct KeyNameBuf {
        name_length: u32,
        name: [u16; MAX_REG_PATH],
    }

    let mut buf = KeyNameBuf {
        name_length: 0,
        name: [0; MAX_REG_PATH],
    };
    let mut size: u32 = 0;

    let status = unsafe {
        NtQueryKey(
            key as _,
            3, // KeyNameInformation
            &mut buf as *mut _ as *mut _,
            std::mem::size_of::<KeyNameBuf>() as u32,
            &mut size,
        )
    };

    unsafe {
        SetLastError(last_error);
    }

    if status == 0 && buf.name_length > 0 {
        let chars_len = (buf.name_length as usize / 2).min(MAX_REG_PATH);
        from_wide_null(&buf.name[..chars_len])
    } else {
        format!("0x{:p}", key)
    }
}
