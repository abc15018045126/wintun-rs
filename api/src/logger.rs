use std::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_ARGUMENT_ARRAY,
    FORMAT_MESSAGE_FROM_STRING, FORMAT_MESSAGE_FROM_SYSTEM,
};

use crate::ntdll::{NtQueryKey, NtQuerySystemTime};
use crate::types::{
    from_wide_null, get_last_error, set_last_error, to_wide, WintunLoggerCallback,
    WintunLoggerLevel, FORMAT_MESSAGE_MAX_WIDTH_MASK, HKEY, MAX_REG_PATH,
};

unsafe extern "system" fn nop_logger(
    _level: WintunLoggerLevel,
    _timestamp: u64,
    _message: *const u16,
) {
}

static LOGGER_CALLBACK: AtomicPtr<()> = AtomicPtr::new(nop_logger as *mut ());

#[inline]
pub fn is_logger_active() -> bool {
    LOGGER_CALLBACK.load(Ordering::Relaxed) != nop_logger as *mut ()
}

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

#[inline]
pub fn log_msg(level: WintunLoggerLevel, message: &str) -> u32 {
    let last_error = get_last_error();
    if !is_logger_active() {
        return last_error;
    }
    let wide_msg = to_wide(message);
    let logger = get_logger();
    unsafe {
        logger(level, now(), wide_msg.as_ptr());
    }
    set_last_error(last_error);
    last_error
}

pub fn hresult_from_setupapi(error: u32) -> u32 {
    const APPLICATION_ERROR_MASK: u32 = 0x20000000;
    const ERROR_SEVERITY_ERROR: u32 = 0xC0000000;
    const FACILITY_SETUPAPI: u32 = 15;
    const FACILITY_WIN32: u32 = 7;

    if (error & (APPLICATION_ERROR_MASK | ERROR_SEVERITY_ERROR))
        == (APPLICATION_ERROR_MASK | ERROR_SEVERITY_ERROR)
    {
        (error & 0x0000FFFF) | (FACILITY_SETUPAPI << 16) | 0x80000000
    } else if error == 0 {
        0
    } else {
        (error & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000
    }
}

pub fn log_error_wide(error: u32, prefix: *const u16) -> u32 {
    if !is_logger_active() {
        return error;
    }

    let mut system_message: *mut u16 = std::ptr::null_mut();
    let mut formatted_message: *mut u16 = std::ptr::null_mut();

    unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            std::ptr::null(),
            hresult_from_setupapi(error),
            0x0400, // MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
            &mut system_message as *mut *mut u16 as *mut u16,
            0,
            std::ptr::null_mut(),
        );

        let fmt_str = if !system_message.is_null() {
            windows_sys::w!("%1: %3(Code 0x%2!08X!)")
        } else {
            windows_sys::w!("%1: Code 0x%2!08X!")
        };

        let args: [usize; 3] = [prefix as usize, error as usize, system_message as usize];

        FormatMessageW(
            FORMAT_MESSAGE_FROM_STRING
                | FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_ARGUMENT_ARRAY
                | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            fmt_str as *const _,
            0,
            0,
            &mut formatted_message as *mut *mut u16 as *mut u16,
            0,
            args.as_ptr() as _,
        );

        if !formatted_message.is_null() {
            let logger = get_logger();
            logger(WintunLoggerLevel::Err, now(), formatted_message);
            crate::types::LocalFree(formatted_message as _);
        }

        if !system_message.is_null() {
            crate::types::LocalFree(system_message as _);
        }
    }

    error
}

#[inline]
pub fn log_error(error: u32, prefix: &str) -> u32 {
    if !is_logger_active() {
        return error;
    }
    let prefix_wide = to_wide(prefix);
    log_error_wide(error, prefix_wide.as_ptr())
}

#[inline]
pub fn log_last_error(prefix: &str) -> u32 {
    let last_error = get_last_error();
    if is_logger_active() {
        log_error(last_error, prefix);
        set_last_error(last_error);
    }
    last_error
}

pub fn get_registry_key_path(key: HKEY) -> String {
    let last_error = get_last_error();
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

    set_last_error(last_error);

    if status == 0 && buf.name_length > 0 {
        let chars_len = (buf.name_length as usize / 2).min(MAX_REG_PATH);
        from_wide_null(&buf.name[..chars_len])
    } else {
        format!("0x{:p}", key)
    }
}
