use std::ffi::c_void;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiBuildDriverInfoList, SetupDiCreateDeviceInfoListExW, SetupDiCreateDeviceInfoW,
    SetupDiDestroyDeviceInfoList, SetupDiDestroyDriverInfoList, SetupDiEnumDriverInfoW,
    SetupDiGetClassDevsExW, SetupDiGetDriverInfoDetailW, SetupDiSetDeviceRegistryPropertyW,
    SetupUninstallOEMInfW, DICD_GENERATE_ID, DIGCF_PRESENT, HDEVINFO, SPDIT_COMPATDRIVER,
    SPDRP_HARDWAREID, SP_DEVINFO_DATA,
};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME,
};
use windows_sys::Win32::Storage::FileSystem::{DeleteFileW, RemoveDirectoryW};

use crate::adapter::{adapter_disable_instance, adapter_enable_instance};
use crate::logger::{is_logger_active, log_last_error, log_msg};
use crate::namespace::namespace_take_driver_installation_mutex;
use crate::ntdll::{
    NtQuerySystemInformation, RtlNtStatusToDosError, RtlProcessModuleInformation,
    RtlProcessModules, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS, SYSTEM_MODULE_INFORMATION,
};
use crate::resource::{
    resource_copy_to_file, resource_create_temporary_directory, DRIVER_CAT, DRIVER_INF, DRIVER_SYS,
};
use crate::types::*;

pub const WINTUN_INF_VERSION: u64 = 14u64 << 32;
pub const WINTUN_INF_FILETIME: FILETIME = FILETIME {
    dwLowDateTime: 0x43f04000,
    dwHighDateTime: 0x01d7bfc5,
};

fn is_newer(date1: &FILETIME, ver1: u64, date2: &FILETIME, ver2: u64) -> bool {
    let t1 = ((date1.dwHighDateTime as u64) << 32) | date1.dwLowDateTime as u64;
    let t2 = ((date2.dwHighDateTime as u64) << 32) | date2.dwLowDateTime as u64;
    (t1, ver1) > (t2, ver2)
}

fn enum_driver_info<'a>(
    dev_info: HDEVINFO,
    dev_info_data: &'a SP_DEVINFO_DATA,
    driver_type: u32,
) -> impl Iterator<Item = SP_DRVINFO_DATA_W> + 'a {
    let mut idx = 0;
    std::iter::from_fn(move || loop {
        let mut data = SP_DRVINFO_DATA_W::default();
        if unsafe {
            SetupDiEnumDriverInfoW(
                dev_info,
                dev_info_data,
                driver_type,
                idx,
                &mut data as *mut _ as _,
            )
        } == 0
        {
            if get_last_error() == ERROR_NO_MORE_ITEMS {
                return None;
            }
            idx += 1;
            continue;
        }
        idx += 1;
        return Some(data);
    })
}

fn disable_all_our_adapters(dev_info: HDEVINFO) -> (Vec<SP_DEVINFO_DATA>, u32) {
    let mut disabled = Vec::new();
    let mut last_error = ERROR_SUCCESS;

    for mut dev_info_data in enum_device_info(dev_info) {
        let mut status: u32 = 0;
        let mut problem_code: u32 = 0;
        if unsafe {
            CM_Get_DevNode_Status(&mut status, &mut problem_code, dev_info_data.DevInst, 0)
        } != CR_SUCCESS
            || ((status & DN_HAS_PROBLEM != 0) && problem_code == CM_PROB_DISABLED)
        {
            continue;
        }

        let name = get_adapter_wintun_name(dev_info, &dev_info_data);
        log_msg(
            WintunLoggerLevel::Info,
            &format!("Disabling adapter \"{}\"", name),
        );
        if !adapter_disable_instance(dev_info, &mut dev_info_data) {
            let err = log_last_error(&format!("Failed to disable adapter \"{}\"", name));
            if last_error == ERROR_SUCCESS {
                last_error = err;
            }
            continue;
        }

        disabled.push(dev_info_data);
    }

    (disabled, last_error)
}

pub fn enable_all_our_adapters(dev_info: HDEVINFO, adapters: &[SP_DEVINFO_DATA]) {
    for mut mut_data in adapters.iter().copied() {
        let name = get_adapter_wintun_name(dev_info, &mut_data);
        log_msg(
            WintunLoggerLevel::Info,
            &format!("Enabling adapter \"{}\"", name),
        );
        if !adapter_enable_instance(dev_info, &mut mut_data) {
            log_last_error(&format!("Failed to enable adapter \"{}\"", name));
        }
    }
}

pub fn driver_install_deferred_cleanup(
    dev_info_existing: HDEVINFO,
    existing_adapters: &[SP_DEVINFO_DATA],
) {
    if dev_info_existing != INVALID_HDEVINFO && dev_info_existing != 0 {
        enable_all_our_adapters(dev_info_existing, existing_adapters);
        unsafe {
            SetupDiDestroyDeviceInfoList(dev_info_existing);
        }
    }
}

fn version_of_file(wide_file: *const u16) -> Result<u32, u32> {
    let mut zero: u32 = 0;
    let len = unsafe { GetFileVersionInfoSizeW(wide_file, &mut zero) };
    if len == 0 {
        let file_str = unsafe { from_wide_ptr(wide_file) };
        return Err(log_last_error(&format!(
            "Failed to query {} version info size",
            file_str
        )));
    }

    let mut version_info = vec![0u8; len as usize];
    if unsafe { GetFileVersionInfoW(wide_file, 0, len, version_info.as_mut_ptr() as _) } == 0 {
        let file_str = unsafe { from_wide_ptr(wide_file) };
        return Err(log_last_error(&format!(
            "Failed to get {} version info",
            file_str
        )));
    }

    #[repr(C)]
    struct VsFixedFileInfo {
        _pad: [u32; 2],
        dw_file_version_ms: u32,
    }

    let sub_block = windows_sys::w!("\\");
    let mut fixed_info_ptr: *mut VsFixedFileInfo = std::ptr::null_mut();
    let mut fixed_info_len: u32 = 0;

    if unsafe {
        VerQueryValueW(
            version_info.as_ptr() as _,
            sub_block,
            &mut fixed_info_ptr as *mut *mut VsFixedFileInfo as *mut *mut c_void,
            &mut fixed_info_len,
        )
    } == 0
        || fixed_info_ptr.is_null()
    {
        let file_str = unsafe { from_wide_ptr(wide_file) };
        return Err(log_last_error(&format!(
            "Failed to get {} version info root",
            file_str
        )));
    }

    let version = unsafe { (*fixed_info_ptr).dw_file_version_ms };
    if version == 0 {
        let file_str = unsafe { from_wide_ptr(wide_file) };
        log_msg(
            WintunLoggerLevel::Warn,
            &format!(
                "Determined version of {}, but was v0.0, so returning failure",
                file_str
            ),
        );
        set_last_error(ERROR_VERSION_PARSE_ERROR);
        return Err(ERROR_VERSION_PARSE_ERROR);
    }

    Ok(version)
}

fn maybe_get_running_driver_version(return_one_if_running: bool) -> Result<u32, u32> {
    let mut buffer_size: u32 = 128 * 1024;
    let mut modules_buf = Vec::new();

    loop {
        modules_buf.resize(buffer_size as usize, 0);
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_MODULE_INFORMATION,
                modules_buf.as_mut_ptr() as _,
                buffer_size,
                &mut buffer_size,
            )
        };

        if status == STATUS_SUCCESS {
            break;
        }

        if status == STATUS_INFO_LENGTH_MISMATCH {
            buffer_size += 32 * 1024;
            continue;
        }

        let dos_err = unsafe { RtlNtStatusToDosError(status) };
        log_msg(
            WintunLoggerLevel::Err,
            &format!("Failed to enumerate drivers (status: 0x{:x})", status),
        );
        set_last_error(dos_err);
        return Err(dos_err);
    }

    let modules_header = unsafe { &*(modules_buf.as_ptr() as *const RtlProcessModules) };
    let count = modules_header.number_of_modules as usize;
    let elem_size = std::mem::size_of::<RtlProcessModuleInformation>();
    let max_count = modules_buf.len().saturating_sub(8) / elem_size;
    let safe_count = count.min(max_count);
    let modules_slice =
        unsafe { std::slice::from_raw_parts(modules_header.modules.as_ptr(), safe_count) };

    for item in modules_slice.iter().rev() {
        let null_pos = item
            .full_path_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(item.full_path_name.len());
        let offset = item.offset_to_file_name as usize;

        if offset <= null_pos
            && item.full_path_name[offset..null_pos].eq_ignore_ascii_case(b"wintun.sys")
        {
            if return_one_if_running {
                return Ok(1);
            }
            let mut file_path = [0u16; 512];
            const PREFIX: *const u16 = windows_sys::w!("\\\\?\\GLOBALROOT\0");
            const PREF_LEN: usize = 14;
            unsafe {
                std::ptr::copy_nonoverlapping(PREFIX, file_path.as_mut_ptr(), PREF_LEN);
            }
            let pref_len = PREF_LEN;
            let path_bytes = &item.full_path_name[..null_pos];
            if pref_len + path_bytes.len() >= file_path.len() {
                continue;
            }
            for (i, &b) in path_bytes.iter().enumerate() {
                file_path[pref_len + i] = b as u16;
            }
            file_path[pref_len + path_bytes.len()] = 0;
            let res = version_of_file(file_path.as_ptr());
            if let Ok(ver) = res {
                set_last_error(ERROR_SUCCESS);
                return Ok(ver);
            }
            return res;
        }
    }

    set_last_error(ERROR_FILE_NOT_FOUND);
    Err(ERROR_FILE_NOT_FOUND)
}

pub fn wintun_get_running_driver_version() -> u32 {
    maybe_get_running_driver_version(false).unwrap_or(0)
}

fn ensure_wintun_unloaded() -> bool {
    for tries in 0..1500 {
        if tries > 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if maybe_get_running_driver_version(true).is_err() {
            return true;
        }
    }
    false
}

fn create_wintun_compat_driver_list() -> Option<(HDEVINFO, SP_DEVINFO_DATA)> {
    let mut dev_info = DeviceInfoSet::new(unsafe {
        SetupDiCreateDeviceInfoListExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    });
    if dev_info.is_invalid() {
        log_last_error("Failed to create empty device information set");
        return None;
    }

    let mut dev_info_data = new_dev_info_data();
    let wintun_hwid = windows_sys::w!("Wintun");
    let hwids_multi = windows_sys::w!("Wintun\0");
    if unsafe {
        SetupDiCreateDeviceInfoW(
            dev_info.raw(),
            wintun_hwid,
            &GUID_DEVCLASS_NET as *const _ as *const _,
            std::ptr::null(),
            std::ptr::null_mut(),
            DICD_GENERATE_ID,
            &mut dev_info_data,
        )
    } == 0
    {
        log_last_error("Failed to create new device information element");
        return None;
    }

    if unsafe {
        SetupDiSetDeviceRegistryPropertyW(
            dev_info.raw(),
            &mut dev_info_data,
            SPDRP_HARDWAREID,
            hwids_multi as _,
            16,
        )
    } == 0
    {
        log_last_error("Failed to set adapter hardware ID");
        return None;
    }

    if unsafe { SetupDiBuildDriverInfoList(dev_info.raw(), &mut dev_info_data, SPDIT_COMPATDRIVER) }
        == 0
    {
        log_last_error("Failed building adapter driver info list");
        return None;
    }

    Some((dev_info.take(), dev_info_data))
}

fn get_driver_inf_name_ptr(
    dev_info: HDEVINFO,
    dev_info_data: &SP_DEVINFO_DATA,
    drv_info_data: &mut SP_DRVINFO_DATA_W,
    detail_buf: &mut [u8; 0x2000],
) -> Option<*const u16> {
    let detail_ptr = detail_buf.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W;
    unsafe {
        (*detail_ptr).cb_size = std::mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32;
    }
    let mut req_size: u32 = 0;
    if unsafe {
        SetupDiGetDriverInfoDetailW(
            dev_info,
            dev_info_data,
            drv_info_data as *mut _ as _,
            detail_ptr as _,
            detail_buf.len() as u32,
            &mut req_size,
        )
    } != 0
    {
        Some(unsafe { PathFindFileNameW((*detail_ptr).inf_file_name.as_ptr()) })
    } else {
        log_msg(
            WintunLoggerLevel::Warn,
            "Failed getting adapter driver info detail",
        );
        None
    }
}

pub fn driver_install() -> Result<(HDEVINFO, Vec<SP_DEVINFO_DATA>), u32> {
    let _mutex = match namespace_take_driver_installation_mutex() {
        Some(m) => m,
        None => {
            log_msg(
                WintunLoggerLevel::Err,
                "Failed to take driver installation mutex",
            );
            return Err(get_last_error());
        }
    };

    let (dev_info, dev_info_data) = match create_wintun_compat_driver_list() {
        Some(res) => res,
        None => {
            return Err(get_last_error());
        }
    };

    let our_driver_date = WINTUN_INF_FILETIME;
    let our_driver_version = WINTUN_INF_VERSION;

    let mut dev_info_existing = INVALID_HDEVINFO;
    let mut existing_adapters: Vec<SP_DEVINFO_DATA> = Vec::new();
    let mut existing_version: u64 = 0;
    let mut existing_date = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };

    for mut drv_info_data in enum_driver_info(dev_info, &dev_info_data, SPDIT_COMPATDRIVER) {
        if is_newer(
            &our_driver_date,
            our_driver_version,
            &drv_info_data.driver_date,
            drv_info_data.driver_version,
        ) {
            if dev_info_existing == INVALID_HDEVINFO || dev_info_existing == 0 {
                dev_info_existing = unsafe {
                    SetupDiGetClassDevsExW(
                        &GUID_DEVCLASS_NET as *const _ as *const _,
                        windows_sys::w!("SWD\\Wintun"),
                        std::ptr::null_mut(),
                        DIGCF_PRESENT,
                        0,
                        std::ptr::null(),
                        std::ptr::null(),
                    )
                };

                if dev_info_existing == INVALID_HDEVINFO || dev_info_existing == 0 {
                    let last_err = log_last_error("Failed to get present adapters");
                    unsafe {
                        SetupDiDestroyDriverInfoList(dev_info, &dev_info_data, SPDIT_COMPATDRIVER);
                        SetupDiDestroyDeviceInfoList(dev_info);
                    }
                    driver_install_deferred_cleanup(dev_info_existing, &existing_adapters);
                    return Err(last_err);
                }

                let (dis, _) = disable_all_our_adapters(dev_info_existing);
                existing_adapters = dis;
                log_msg(
                    WintunLoggerLevel::Info,
                    "Waiting for existing driver to unload from kernel",
                );
                if !ensure_wintun_unloaded() {
                    log_msg(
                        WintunLoggerLevel::Warn,
                        "Failed to unload existing driver, which means a reboot will likely be required",
                    );
                }
            }

            log_msg(
                WintunLoggerLevel::Info,
                &format!(
                    "Removing existing driver {}.{}",
                    (drv_info_data.driver_version >> 48) & 0xFFFF,
                    (drv_info_data.driver_version >> 32) & 0xFFFF
                ),
            );

            let mut detail_buf = [0u8; 0x2000];
            if let Some(inf_name_ptr) = get_driver_inf_name_ptr(
                dev_info,
                &dev_info_data,
                &mut drv_info_data,
                &mut detail_buf,
            ) {
                if unsafe {
                    SetupUninstallOEMInfW(
                        inf_name_ptr,
                        0x0001, /* SUOI_FORCEDELETE */
                        std::ptr::null_mut(),
                    )
                } == 0
                    && is_logger_active()
                {
                    let inf_name = unsafe { from_wide_ptr(inf_name_ptr) };
                    log_last_error(&format!("Unable to remove existing driver {}", inf_name));
                }
            }
            continue;
        }

        if !is_newer(
            &drv_info_data.driver_date,
            drv_info_data.driver_version,
            &existing_date,
            existing_version,
        ) {
            continue;
        }
        existing_date = drv_info_data.driver_date;
        existing_version = drv_info_data.driver_version;
    }

    unsafe {
        SetupDiDestroyDriverInfoList(dev_info, &dev_info_data, SPDIT_COMPATDRIVER);
        SetupDiDestroyDeviceInfoList(dev_info);
    }

    if existing_version > 0 {
        log_msg(
            WintunLoggerLevel::Info,
            &format!(
                "Using existing driver {}.{}",
                (existing_version >> 48) & 0xFFFF,
                (existing_version >> 32) & 0xFFFF
            ),
        );
        return Ok((dev_info_existing, existing_adapters));
    }

    log_msg(
        WintunLoggerLevel::Info,
        &format!(
            "Installing driver {}.{}",
            (our_driver_version >> 48) & 0xFFFF,
            (our_driver_version >> 32) & 0xFFFF
        ),
    );

    let mut temp_dir = [0u16; 260];
    if let Err(e) = resource_create_temporary_directory(&mut temp_dir) {
        driver_install_deferred_cleanup(dev_info_existing, &existing_adapters);
        return Err(e);
    }

    let mut cat_path = [0u16; 260];
    let mut sys_path = [0u16; 260];
    let mut inf_path = [0u16; 260];

    const CAT_NAME: *const u16 = windows_sys::w!("wintun.cat");
    const SYS_NAME: *const u16 = windows_sys::w!("wintun.sys");
    const INF_NAME: *const u16 = windows_sys::w!("wintun.inf");

    if unsafe { PathCombineW(cat_path.as_mut_ptr(), temp_dir.as_ptr(), CAT_NAME) }.is_null()
        || unsafe { PathCombineW(sys_path.as_mut_ptr(), temp_dir.as_ptr(), SYS_NAME) }.is_null()
        || unsafe { PathCombineW(inf_path.as_mut_ptr(), temp_dir.as_ptr(), INF_NAME) }.is_null()
    {
        unsafe {
            RemoveDirectoryW(temp_dir.as_ptr());
        }
        set_last_error(ERROR_BUFFER_OVERFLOW);
        driver_install_deferred_cleanup(dev_info_existing, &existing_adapters);
        return Err(ERROR_BUFFER_OVERFLOW);
    }

    log_msg(WintunLoggerLevel::Info, "Extracting driver");
    let extract_ok = resource_copy_to_file(cat_path.as_ptr(), DRIVER_CAT).is_ok()
        && resource_copy_to_file(sys_path.as_ptr(), DRIVER_SYS).is_ok()
        && resource_copy_to_file(inf_path.as_ptr(), DRIVER_INF).is_ok();

    if !extract_ok {
        let last_err = log_last_error("Failed to extract driver");
        unsafe {
            DeleteFileW(cat_path.as_ptr());
            DeleteFileW(sys_path.as_ptr());
            DeleteFileW(inf_path.as_ptr());
            RemoveDirectoryW(temp_dir.as_ptr());
        }
        driver_install_deferred_cleanup(dev_info_existing, &existing_adapters);
        return Err(last_err);
    }

    log_msg(WintunLoggerLevel::Info, "Installing driver");

    let install_res = unsafe {
        SetupCopyOEMInfW(
            inf_path.as_ptr(),
            std::ptr::null(),
            0, // SPOST_NONE
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    let last_err = if install_res == 0 {
        let err = get_last_error();
        if is_logger_active() {
            log_last_error(&format!("Could not install driver {} to store", unsafe {
                from_wide_ptr(inf_path.as_ptr())
            }));
        }
        err
    } else {
        ERROR_SUCCESS
    };

    unsafe {
        DeleteFileW(cat_path.as_ptr());
        DeleteFileW(sys_path.as_ptr());
        DeleteFileW(inf_path.as_ptr());
        RemoveDirectoryW(temp_dir.as_ptr());
    }

    if last_err != ERROR_SUCCESS {
        driver_install_deferred_cleanup(dev_info_existing, &existing_adapters);
        return Err(last_err);
    }

    Ok((dev_info_existing, existing_adapters))
}

pub fn wintun_delete_driver() -> bool {
    crate::adapter::adapter_cleanup_orphaned_devices();

    let _mutex = match namespace_take_driver_installation_mutex() {
        Some(m) => m,
        None => {
            log_msg(
                WintunLoggerLevel::Err,
                "Failed to take driver installation mutex",
            );
            return false;
        }
    };

    let (dev_info, dev_info_data) = match create_wintun_compat_driver_list() {
        Some(res) => res,
        None => {
            let last_error = get_last_error();
            drop(_mutex);
            set_last_error(last_error);
            return false;
        }
    };

    let mut last_error = ERROR_SUCCESS;
    for mut drv_info_data in enum_driver_info(dev_info, &dev_info_data, SPDIT_COMPATDRIVER) {
        let mut detail_buf = [0u8; 0x2000];
        if let Some(inf_name_ptr) = get_driver_inf_name_ptr(
            dev_info,
            &dev_info_data,
            &mut drv_info_data,
            &mut detail_buf,
        ) {
            if is_logger_active() {
                let inf_name = unsafe { from_wide_ptr(inf_name_ptr) };
                log_msg(
                    WintunLoggerLevel::Info,
                    &format!("Removing driver {}", inf_name),
                );
            }
            if unsafe { SetupUninstallOEMInfW(inf_name_ptr, 0, std::ptr::null_mut()) } == 0 {
                let err = if is_logger_active() {
                    let inf_name = unsafe { from_wide_ptr(inf_name_ptr) };
                    log_last_error(&format!("Unable to remove driver {}", inf_name))
                } else {
                    get_last_error()
                };
                if last_error == ERROR_SUCCESS {
                    last_error = err;
                }
            }
        }
    }

    unsafe {
        SetupDiDestroyDriverInfoList(dev_info, &dev_info_data, SPDIT_COMPATDRIVER);
        SetupDiDestroyDeviceInfoList(dev_info);
    }

    drop(_mutex);

    if last_error != ERROR_SUCCESS {
        set_last_error(last_error);
        false
    } else {
        true
    }
}
