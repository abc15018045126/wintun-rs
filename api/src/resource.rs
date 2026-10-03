use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_GEN_FAILURE, ERROR_SUCCESS, ERROR_WRITE_FAULT,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, WriteFile, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_TEMPORARY,
};

use crate::logger::{log_last_error, log_msg};
use crate::namespace::get_security_attributes;
use crate::ntdll::RtlGenRandom;
use crate::types::{
    from_wide_ptr, set_last_error, GetWindowsDirectoryW, PathCombineW, WintunLoggerLevel,
};

pub const DRIVER_CAT: &[u8] = include_bytes!("../Release/amd64/driver/wintun.cat");
pub const DRIVER_INF: &[u8] = include_bytes!("../Release/amd64/driver/wintun.inf");
pub const DRIVER_SYS: &[u8] = include_bytes!("../Release/amd64/driver/wintun.sys");

const GENERIC_WRITE: u32 = 0x40000000;

pub fn resource_create_temporary_directory(out_path: &mut [u16; 260]) -> Result<(), u32> {
    let mut win_dir = [0u16; 260];
    let win_len = unsafe { GetWindowsDirectoryW(win_dir.as_mut_ptr(), win_dir.len() as u32) };
    if win_len == 0 {
        return Err(log_last_error("Failed to get Windows folder"));
    }

    let mut win_temp_dir = [0u16; 260];
    if unsafe {
        PathCombineW(
            win_temp_dir.as_mut_ptr(),
            win_dir.as_ptr(),
            windows_sys::w!("Temp"),
        )
    }
    .is_null()
    {
        set_last_error(ERROR_BUFFER_OVERFLOW);
        return Err(ERROR_BUFFER_OVERFLOW);
    }

    let mut random_bytes = [0u8; 32];
    if unsafe { RtlGenRandom(random_bytes.as_mut_ptr() as _, random_bytes.len() as u32) } == 0 {
        log_msg(WintunLoggerLevel::Err, "Failed to generate random");
        set_last_error(ERROR_GEN_FAILURE);
        return Err(ERROR_GEN_FAILURE);
    }

    let mut random_sub_dir = [0u16; 65];
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in random_bytes.iter().enumerate() {
        random_sub_dir[i * 2] = HEX_CHARS[(b >> 4) as usize] as u16;
        random_sub_dir[i * 2 + 1] = HEX_CHARS[(b & 0x0F) as usize] as u16;
    }
    random_sub_dir[64] = 0;

    if unsafe {
        PathCombineW(
            out_path.as_mut_ptr(),
            win_temp_dir.as_ptr(),
            random_sub_dir.as_ptr(),
        )
    }
    .is_null()
    {
        set_last_error(ERROR_BUFFER_OVERFLOW);
        return Err(ERROR_BUFFER_OVERFLOW);
    }

    let Some(sec_attr) = get_security_attributes() else {
        set_last_error(windows_sys::Win32::Foundation::ERROR_OUTOFMEMORY);
        return Err(windows_sys::Win32::Foundation::ERROR_OUTOFMEMORY);
    };

    if unsafe { CreateDirectoryW(out_path.as_ptr(), &sec_attr) } == 0 {
        let err = log_last_error(&format!("Failed to create temporary folder {}", unsafe {
            from_wide_ptr(out_path.as_ptr())
        }));
        return Err(err);
    }

    Ok(())
}

pub fn resource_copy_to_file(destination_path: *const u16, content: &[u8]) -> Result<(), u32> {
    let Some(sec_attr) = get_security_attributes() else {
        set_last_error(windows_sys::Win32::Foundation::ERROR_OUTOFMEMORY);
        return Err(windows_sys::Win32::Foundation::ERROR_OUTOFMEMORY);
    };

    let handle_raw = unsafe {
        CreateFileW(
            destination_path,
            GENERIC_WRITE,
            0,
            &sec_attr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
            std::ptr::null_mut(),
        )
    };

    if handle_raw == INVALID_HANDLE_VALUE || handle_raw.is_null() {
        let err = log_last_error(&format!("Failed to create file {}", unsafe {
            from_wide_ptr(destination_path)
        }));
        return Err(err);
    }

    let mut bytes_written: u32 = 0;
    let write_res = unsafe {
        WriteFile(
            handle_raw,
            content.as_ptr(),
            content.len() as u32,
            &mut bytes_written,
            std::ptr::null_mut(),
        )
    };

    let last_error = if write_res == 0 {
        log_last_error(&format!("Failed to write file {}", unsafe {
            from_wide_ptr(destination_path)
        }))
    } else if bytes_written != content.len() as u32 {
        log_msg(
            WintunLoggerLevel::Err,
            &format!(
                "Incomplete write to {} (written: {}, expected: {})",
                unsafe { from_wide_ptr(destination_path) },
                bytes_written,
                content.len()
            ),
        );
        ERROR_WRITE_FAULT
    } else {
        ERROR_SUCCESS
    };

    unsafe {
        CloseHandle(handle_raw);
    }

    if last_error != ERROR_SUCCESS {
        set_last_error(last_error);
        return Err(last_error);
    }

    Ok(())
}
