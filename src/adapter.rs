// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.

use crate::ntdll::RtlNtStatusToDosError;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_DEVICE_NOT_AVAILABLE, ERROR_GEN_FAILURE,
    ERROR_INVALID_DATA, ERROR_NOT_FOUND, ERROR_SUCCESS, ERROR_TIMEOUT, HANDLE,
    INVALID_HANDLE_VALUE,
};

pub const ERROR_DEVICE_ENUMERATION_ERROR: u32 = 508;
pub const ERROR_PNP_REGISTRY_ERROR: u32 = 509;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiCallClassInstaller, SetupDiCreateDeviceInfoListExW, SetupDiDestroyDeviceInfoList,
    SetupDiGetClassDevsExW, SetupDiGetDeviceInstanceIdW, SetupDiOpenDevRegKey,
    SetupDiOpenDeviceInfoW, SetupDiSetClassInstallParamsW, CR_SUCCESS, DICS_DISABLE, DICS_ENABLE,
    DICS_FLAG_GLOBAL, DIF_PROPERTYCHANGE, DIF_REMOVE, DIGCF_PRESENT, DIOD_INHERIT_CLASSDRVS,
    DIREG_DRV, HDEVINFO, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_PROPCHANGE_PARAMS,
    SP_REMOVEDEVICE_PARAMS,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Registry::{RegCloseKey, RegSetValueExW, REG_BINARY};
use windows_sys::Win32::System::Threading::{
    CreateEventW, QueueUserWorkItem, SetEvent, WaitForSingleObject, INFINITE,
};

use crate::driver::{driver_install, driver_install_deferred_cleanup};
use crate::logger::{get_registry_key_path, log_error, log_last_error, log_msg};
use crate::namespace::{namespace_release_mutex, namespace_take_device_installation_mutex};
use crate::nci::nci_set_adapter_name;
use crate::registry::{registry_query_dword, registry_query_string};
use crate::types::*;

pub use crate::types::DEVPKEY_WINTUN_NAME;

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;

#[link(name = "cfgmgr32")]
extern "system" {
    fn CM_Locate_DevNodeW(pdn_dev_inst: *mut u32, p_device_id: *const u16, ul_flags: u32) -> u32;
    fn CM_Get_Device_IDW(dn_dev_inst: u32, buffer: *mut u16, buffer_len: u32, ul_flags: u32)
        -> u32;
    fn CM_Open_DevNode_Key(
        dn_dev_inst: u32,
        sam_desired: u32,
        ul_hardware_profile: u32,
        disposition: u32,
        phk_device: *mut HKEY,
        ul_flags: u32,
    ) -> u32;
    fn CM_Get_Device_Interface_List_SizeW(
        pul_len: *mut u32,
        interface_class_guid: *const GUID,
        p_device_id: *const u16,
        ul_flags: u32,
    ) -> u32;
    fn CM_Get_Device_Interface_ListW(
        interface_class_guid: *const GUID,
        p_device_id: *const u16,
        buffer: *mut u16,
        buffer_len: u32,
        ul_flags: u32,
    ) -> u32;
    fn CM_MapCrToWin32Err(cm_ret: u32, default_err: u32) -> u32;

    fn SwDeviceCreate(
        psz_device_enumerator: *const u16,
        psz_parent_device_instance_id: *const u16,
        p_create_info: *const SwDeviceCreateInfo,
        c_property_count: u32,
        p_properties: *const DevProperty,
        p_callback: SwDeviceCreateCallback,
        p_context: *mut c_void,
        ph_sw_device: *mut HSWDEVICE,
    ) -> i32;

    fn SwDeviceClose(h_sw_device: HSWDEVICE);

    fn DevCreateObjectQuery(
        query_type: u32,
        flags: u32,
        c_requested_properties: u32,
        p_requested_properties: *const DevPropCompKey,
        c_filter_expression_count: u32,
        p_filter: *const DevPropFilterExpression,
        p_callback: DevQueryCallback,
        p_context: *mut c_void,
        ph_dev_query: *mut HDEVQUERY,
    ) -> i32;
    fn DevCloseObjectQuery(h_dev_query: HDEVQUERY);
}

const CM_LOCATE_DEVNODE_NORMAL: u32 = 0x00000000;
const CM_LOCATE_DEVNODE_PHANTOM: u32 = 0x00000001;
const CM_REGISTRY_SOFTWARE: u32 = 0x00000001;
const REG_DISPOSITION_OPEN_ALWAYS: u32 = 0x00000000;
const CM_GET_DEVICE_INTERFACE_LIST_PRESENT: u32 = 0x00000000;
const DN_HAS_PROBLEM: u32 = 0x00000400;

struct SwDeviceCreateContext {
    create_result: i32,
    device_instance_id: [u16; MAX_DEVICE_ID_LEN],
    triggered: HANDLE,
}

unsafe extern "system" fn device_create_callback(
    _h_sw_device: HSWDEVICE,
    create_result: i32,
    p_context: *mut c_void,
    psz_device_instance_id: *const u16,
) {
    let ctx = &mut *(p_context as *mut SwDeviceCreateContext);
    ctx.create_result = create_result;
    if !psz_device_instance_id.is_null() {
        let len = (0..MAX_DEVICE_ID_LEN)
            .position(|i| *psz_device_instance_id.add(i) == 0)
            .unwrap_or(MAX_DEVICE_ID_LEN - 1);
        std::ptr::copy_nonoverlapping(
            psz_device_instance_id,
            ctx.device_instance_id.as_mut_ptr(),
            len,
        );
        ctx.device_instance_id[len] = 0;
    }
    SetEvent(ctx.triggered);
}

struct WaitForInterfaceCtx {
    event: HANDLE,
    last_error: u32,
}

unsafe extern "system" fn wait_for_interface_callback(
    _dev_query: HDEVQUERY,
    context: *mut c_void,
    action_data: *const DevQueryResultActionData,
) {
    let ctx = &mut *(context as *mut WaitForInterfaceCtx);
    let mut ret = ERROR_SUCCESS;
    match (*action_data).action {
        DEV_QUERY_RESULT_STATE_CHANGE => {
            if unsafe { (*action_data).data.state } != DEV_QUERY_STATE_ABORTED {
                return;
            }
            ret = ERROR_DEVICE_NOT_AVAILABLE;
        }
        DEV_QUERY_RESULT_ADD | DEV_QUERY_RESULT_UPDATE => {}
        _ => return,
    }
    ctx.last_error = ret;
    SetEvent(ctx.event);
}

fn wait_for_interface(instance_id: &str) -> bool {
    let wide_instance = to_wide(instance_id);
    let dev_prop_true: i8 = DEVPROP_TRUE;

    let filters = [
        DevPropFilterExpression::new(
            DEVPROP_OPERATOR_EQUALS_IGNORE_CASE,
            DevProperty::system(
                DEVPKEY_DEVICE_INSTANCE_ID,
                DEVPROP_TYPE_STRING,
                wide_instance.as_ptr() as _,
                wide_instance.len() * 2,
            ),
        ),
        DevPropFilterExpression::new(
            DEVPROP_OPERATOR_EQUALS,
            DevProperty::system(
                DEVPKEY_DEVICE_INTERFACE_ENABLED,
                DEVPROP_TYPE_BOOLEAN,
                &dev_prop_true as *const _ as _,
                1,
            ),
        ),
        DevPropFilterExpression::new(
            DEVPROP_OPERATOR_EQUALS,
            DevProperty::system(
                DEVPKEY_DEVICE_INTERFACE_CLASS_GUID,
                DEVPROP_TYPE_GUID,
                &GUID_DEVINTERFACE_NET as *const _ as _,
                std::mem::size_of::<GUID>(),
            ),
        ),
    ];

    let event = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
    if event.is_null() {
        log_last_error("Failed to create event");
        return false;
    }

    let mut ctx = WaitForInterfaceCtx {
        event,
        last_error: ERROR_SUCCESS,
    };

    let mut query: HDEVQUERY = std::ptr::null_mut();
    let hr = unsafe {
        DevCreateObjectQuery(
            DEV_OBJECT_TYPE_DEVICE_INTERFACE,
            DEV_QUERY_FLAG_UPDATE_RESULTS,
            0,
            std::ptr::null(),
            filters.len() as u32,
            filters.as_ptr(),
            wait_for_interface_callback,
            &mut ctx as *mut _ as *mut c_void,
            &mut query,
        )
    };

    if hr < 0 {
        unsafe { CloseHandle(event) };
        // Fallback to polling CM_Get_Device_Interface_List_SizeW if DevCreateObjectQuery is unsupported
        for _ in 0..100 {
            let mut len: u32 = 0;
            let cr = unsafe {
                CM_Get_Device_Interface_List_SizeW(
                    &mut len,
                    &GUID_DEVINTERFACE_NET,
                    wide_instance.as_ptr(),
                    CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
                )
            };
            if cr == CR_SUCCESS && len > 1 {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        log_error(hr as u32, "Failed to create device query");
        unsafe { SetLastError(hr as u32) };
        return false;
    }

    let mut last_error = ERROR_TIMEOUT;
    for _ in 0..300 {
        let wait_res = unsafe { WaitForSingleObject(event, 50) };
        if wait_res == 0 {
            last_error = ctx.last_error;
            break;
        } else if wait_res == 0xFFFFFFFF {
            log_last_error("Failed to wait for device query");
            last_error = unsafe { GetLastError() };
            break;
        }

        // Active probe: if the interface is already enabled and present in CfgMgr, succeed immediately
        let mut len: u32 = 0;
        let cr = unsafe {
            CM_Get_Device_Interface_List_SizeW(
                &mut len,
                &GUID_DEVINTERFACE_NET,
                wide_instance.as_ptr(),
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            )
        };
        if cr == CR_SUCCESS && len > 1 {
            last_error = ERROR_SUCCESS;
            break;
        }
    }

    if last_error == ERROR_TIMEOUT {
        log_error(ERROR_TIMEOUT, "Timed out waiting for device query");
    } else if last_error != ERROR_SUCCESS {
        log_error(last_error, "Failed to get enabled device");
    }

    unsafe {
        DevCloseObjectQuery(query);
        CloseHandle(event);
    }

    if last_error != ERROR_SUCCESS {
        unsafe { SetLastError(last_error) };
        false
    } else {
        true
    }
}

pub fn adapter_get_device_object_file_name(instance_id: &str) -> Result<String, u32> {
    let wide_instance = to_wide(instance_id);

    for _attempt in 0..20 {
        let mut interfaces_len: u32 = 0;
        let cr = unsafe {
            CM_Get_Device_Interface_List_SizeW(
                &mut interfaces_len,
                &GUID_DEVINTERFACE_NET,
                wide_instance.as_ptr(),
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            )
        };

        if cr == CR_SUCCESS && interfaces_len > 1 {
            let mut interfaces = vec![0u16; interfaces_len as usize];
            let cr2 = unsafe {
                CM_Get_Device_Interface_ListW(
                    &GUID_DEVINTERFACE_NET,
                    wide_instance.as_ptr(),
                    interfaces.as_mut_ptr(),
                    interfaces_len,
                    CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
                )
            };

            if cr2 == CR_SUCCESS && !interfaces.is_empty() && interfaces[0] != 0 {
                return Ok(from_wide_null(&interfaces));
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    log_msg(
        WintunLoggerLevel::Err,
        &format!("Failed to get adapter {} associated interface", instance_id),
    );
    unsafe { SetLastError(ERROR_DEVICE_NOT_AVAILABLE) };
    Err(ERROR_DEVICE_NOT_AVAILABLE)
}

fn populate_adapter_data(adapter: &mut WintunAdapter) -> bool {
    let mut key: HKEY = std::ptr::null_mut();
    let mut value_str = String::new();

    for attempt in 0..20 {
        key = unsafe {
            SetupDiOpenDevRegKey(
                adapter.dev_info,
                &adapter.dev_info_data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DRV,
                windows_sys::Win32::System::Registry::KEY_QUERY_VALUE,
            )
        };

        if !std::ptr::eq(key, INVALID_HANDLE_VALUE as HKEY) && !key.is_null() {
            let log_err = attempt == 19;
            if let Ok(s) = registry_query_string(key, Some("NetCfgInstanceId"), log_err) {
                value_str = s;
                break;
            }
            unsafe { RegCloseKey(key) };
            key = std::ptr::null_mut();
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    if key.is_null() || value_str.is_empty() {
        log_msg(
            WintunLoggerLevel::Err,
            "Failed to open adapter device registry key / query NetCfgInstanceId",
        );
        return false;
    }

    let wide_val = to_wide(&value_str);
    let hr = unsafe { CLSIDFromString(wide_val.as_ptr(), &mut adapter.cfg_instance_id) };
    if hr < 0 {
        let reg_path = get_registry_key_path(key);
        log_msg(
            WintunLoggerLevel::Err,
            &format!(
                "{}\\{} is not a GUID: {}",
                reg_path, "NetCfgInstanceId", value_str
            ),
        );
        unsafe { RegCloseKey(key) };
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return false;
    }

    let Ok(luid_index) = registry_query_dword(key, Some("NetLuidIndex"), true) else {
        unsafe { RegCloseKey(key) };
        return false;
    };
    adapter.luid_index = luid_index;

    let Ok(if_type) = registry_query_dword(key, Some("*IfType"), true) else {
        unsafe { RegCloseKey(key) };
        return false;
    };
    adapter.if_type = if_type;

    unsafe { RegCloseKey(key) };

    let dev_inst_str = from_wide_null(&adapter.dev_instance_id);

    let filename = match adapter_get_device_object_file_name(&dev_inst_str) {
        Ok(f) => f,
        Err(e) => {
            log_last_error("Unable to determine device object file name");
            unsafe { SetLastError(e) };
            return false;
        }
    };

    adapter.interface_filename = to_wide(&filename);
    true
}

static ORPHAN_THREAD_WORKING: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn do_orphaned_device_cleanup(_ctx: *mut c_void) -> u32 {
    adapter_cleanup_orphaned_devices();
    ORPHAN_THREAD_WORKING.store(false, Ordering::SeqCst);
    0
}

pub fn queue_up_orphaned_device_cleanup_routine() {
    if ORPHAN_THREAD_WORKING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        unsafe {
            QueueUserWorkItem(Some(do_orphaned_device_cleanup), std::ptr::null_mut(), 0);
        }
    }
}

pub fn adapter_cleanup_orphaned_devices() {
    let Some(mutex) = namespace_take_device_installation_mutex() else {
        log_last_error("Failed to take device installation mutex");
        return;
    };

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
        log_last_error("Failed to get adapters");
        namespace_release_mutex(mutex);
        return;
    }

    for mut dev_info_data in enum_device_info(dev_info) {
        let mut status: u32 = 0;
        let mut code: u32 = 0;
        if unsafe { CM_Get_DevNode_Status(&mut status, &mut code, dev_info_data.DevInst, 0) }
            == CR_SUCCESS
            && (status & DN_HAS_PROBLEM) == 0
        {
            continue;
        }

        let trimmed_name = get_adapter_wintun_name(dev_info, &dev_info_data);

        if !adapter_remove_instance(dev_info, &mut dev_info_data) {
            log_last_error(&format!(
                "Failed to remove orphaned adapter \"{}\"",
                trimmed_name
            ));
            continue;
        }
        log_msg(
            WintunLoggerLevel::Info,
            &format!("Removed orphaned adapter \"{}\"", trimmed_name),
        );
    }

    unsafe {
        SetupDiDestroyDeviceInfoList(dev_info);
    }
    namespace_release_mutex(mutex);
}

pub fn adapter_cleanup_legacy_devices() {
    let root_net = to_wide("ROOT\\NET");
    let dev_info = unsafe {
        SetupDiGetClassDevsExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            root_net.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };

    if dev_info == INVALID_HDEVINFO || dev_info == 0 {
        return;
    }

    for mut dev_info_data in enum_device_info(dev_info) {
        let mut hwid_buf = [0u16; 1024];
        let mut val_type: u32 = 0;
        let mut size = (hwid_buf.len() * std::mem::size_of::<u16>()) as u32;

        if unsafe {
            windows_sys::Win32::Devices::DeviceAndDriverInstallation::SetupDiGetDeviceRegistryPropertyW(
                dev_info,
                &dev_info_data,
                windows_sys::Win32::Devices::DeviceAndDriverInstallation::SPDRP_HARDWAREID,
                &mut val_type,
                hwid_buf.as_mut_ptr() as _,
                size,
                &mut size,
            )
        } == 0
        {
            continue;
        }

        let slice = &hwid_buf[..(size as usize / std::mem::size_of::<u16>())];
        for item in slice.split(|&c| c == 0) {
            if !item.is_empty() && String::from_utf16_lossy(item).eq_ignore_ascii_case("Wintun") {
                adapter_remove_instance(dev_info, &mut dev_info_data);
                break;
            }
        }
    }

    unsafe {
        SetupDiDestroyDeviceInfoList(dev_info);
    }
}

pub fn adapter_remove_instance(dev_info: HDEVINFO, dev_info_data: &mut SP_DEVINFO_DATA) -> bool {
    let remove_params = SP_REMOVEDEVICE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_REMOVE,
        },
        Scope: windows_sys::Win32::Devices::DeviceAndDriverInstallation::DI_REMOVEDEVICE_GLOBAL,
        HwProfile: 0,
    };

    let set_ok = unsafe {
        SetupDiSetClassInstallParamsW(
            dev_info,
            dev_info_data,
            &remove_params.ClassInstallHeader,
            std::mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
        )
    };

    set_ok != 0 && unsafe { SetupDiCallClassInstaller(DIF_REMOVE, dev_info, dev_info_data) } != 0
}

fn change_instance_state(
    dev_info: HDEVINFO,
    dev_info_data: &mut SP_DEVINFO_DATA,
    state_change: u32,
) -> bool {
    let params = SP_PROPCHANGE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_PROPERTYCHANGE,
        },
        StateChange: state_change,
        Scope: DICS_FLAG_GLOBAL,
        HwProfile: 0,
    };

    let set_ok = unsafe {
        SetupDiSetClassInstallParamsW(
            dev_info,
            dev_info_data,
            &params.ClassInstallHeader,
            std::mem::size_of::<SP_PROPCHANGE_PARAMS>() as u32,
        )
    };

    set_ok != 0
        && unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, dev_info, dev_info_data) } != 0
}

pub fn adapter_enable_instance(dev_info: HDEVINFO, dev_info_data: &mut SP_DEVINFO_DATA) -> bool {
    change_instance_state(dev_info, dev_info_data, DICS_ENABLE)
}

pub fn adapter_disable_instance(dev_info: HDEVINFO, dev_info_data: &mut SP_DEVINFO_DATA) -> bool {
    change_instance_state(dev_info, dev_info_data, DICS_DISABLE)
}

pub fn adapter_open_device_object(adapter: &WintunAdapter) -> HANDLE {
    let handle = unsafe {
        CreateFileW(
            adapter.interface_filename.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let name_str = String::from_utf16_lossy(&adapter.interface_filename);
        log_last_error(&format!(
            "Failed to connect to adapter interface {}",
            name_str
        ));
    }
    handle
}

fn diagnose_device_problem(dev_inst_str: &str) -> Option<u32> {
    let diag_dev_info = unsafe {
        SetupDiCreateDeviceInfoListExW(
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if diag_dev_info == INVALID_HDEVINFO || diag_dev_info == 0 {
        return None;
    }
    let mut diag_data = new_dev_info_data();
    let wide_inst = to_wide(dev_inst_str);
    let mut err = None;
    if unsafe {
        SetupDiOpenDeviceInfoW(
            diag_dev_info,
            wide_inst.as_ptr(),
            std::ptr::null_mut(),
            DIOD_INHERIT_CLASSDRVS,
            &mut diag_data,
        )
    } != 0
    {
        let mut prop_type = 0;
        let mut problem_code = 0u32;
        let mut problem_status = 0i32;
        let mut size = std::mem::size_of::<u32>() as u32;

        let code_ok = unsafe {
            SetupDiGetDevicePropertyW(
                diag_dev_info,
                &diag_data,
                &DEVPKEY_DEVICE_PROBLEM_CODE,
                &mut prop_type,
                &mut problem_code as *mut _ as _,
                size,
                &mut size,
                0,
            )
        };

        size = std::mem::size_of::<i32>() as u32;
        let status_ok = unsafe {
            SetupDiGetDevicePropertyW(
                diag_dev_info,
                &diag_data,
                &DEVPKEY_DEVICE_PROBLEM_STATUS,
                &mut prop_type,
                &mut problem_status as *mut _ as _,
                size,
                &mut size,
                0,
            )
        };

        if code_ok != 0 && status_ok != 0 && (problem_code != 0 || problem_status != 0) {
            let win32_err = unsafe { RtlNtStatusToDosError(problem_status) };
            log_error(
                win32_err,
                &format!(
                    "Device has problem: 0x{:x}, status: 0x{:x}",
                    problem_code, problem_status as u32
                ),
            );
            err = Some(win32_err);
        }
    }
    unsafe { SetupDiDestroyDeviceInfoList(diag_dev_info) };
    err
}

fn create_stub_device(
    root_node_name: *const u16,
    instance_id_str: *const u16,
    wide_tunnel_name: *const u16,
    instance_guid: &GUID,
) -> Result<(), u32> {
    let triggered = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
    if triggered.is_null() {
        return Err(log_last_error("Failed to create event trigger"));
    }

    let mut create_context = SwDeviceCreateContext {
        create_result: 0,
        device_instance_id: [0; MAX_DEVICE_ID_LEN],
        triggered,
    };
    let mut sw_device: HSWDEVICE = std::ptr::null_mut();
    let empty_hwids: [u16; 2] = [0, 0];
    let stub_create_info =
        SwDeviceCreateInfo::new(instance_id_str, empty_hwids.as_ptr(), wide_tunnel_name);
    let stub_props = [DevProperty::system(
        DEVPKEY_DEVICE_CLASS_GUID,
        DEVPROP_TYPE_GUID,
        &GUID_DEVCLASS_NET as *const _ as _,
        std::mem::size_of::<GUID>(),
    )];

    let wintun_hwid_w = to_wide("Wintun");
    let hr = unsafe {
        SwDeviceCreate(
            wintun_hwid_w.as_ptr(),
            root_node_name,
            &stub_create_info,
            stub_props.len() as u32,
            stub_props.as_ptr(),
            device_create_callback,
            &mut create_context as *mut _ as *mut c_void,
            &mut sw_device,
        )
    };

    if hr < 0 {
        unsafe { CloseHandle(triggered) };
        log_error(hr as u32, "Failed to initiate stub device creation");
        return Err(hr as u32);
    }

    unsafe {
        WaitForSingleObject(triggered, INFINITE);
        CloseHandle(triggered);
    }

    let res = (|| {
        if create_context.create_result < 0 {
            log_error(
                create_context.create_result as u32,
                "Failed to create stub device",
            );
            return Err(create_context.create_result as u32);
        }

        let mut dev_inst: u32 = 0;
        let cr = unsafe {
            CM_Locate_DevNodeW(
                &mut dev_inst,
                create_context.device_instance_id.as_ptr(),
                CM_LOCATE_DEVNODE_PHANTOM,
            )
        };
        if cr != CR_SUCCESS {
            let err = unsafe { CM_MapCrToWin32Err(cr, ERROR_DEVICE_ENUMERATION_ERROR) };
            log_error(err, "Failed to make stub device list");
            return Err(err);
        }

        let mut driver_key: HKEY = std::ptr::null_mut();
        let cr_key = unsafe {
            CM_Open_DevNode_Key(
                dev_inst,
                windows_sys::Win32::System::Registry::KEY_SET_VALUE,
                0,
                REG_DISPOSITION_OPEN_ALWAYS,
                &mut driver_key,
                CM_REGISTRY_SOFTWARE,
            )
        };
        if cr_key != CR_SUCCESS {
            let err = unsafe { CM_MapCrToWin32Err(cr_key, ERROR_PNP_REGISTRY_ERROR) };
            log_error(err, "Failed to create software registry key");
            return Err(err);
        }

        let suggested_id_w = to_wide("SuggestedInstanceId");
        let reg_err = unsafe {
            RegSetValueExW(
                driver_key,
                suggested_id_w.as_ptr(),
                0,
                REG_BINARY,
                instance_guid as *const _ as *const u8,
                std::mem::size_of::<GUID>() as u32,
            )
        };
        unsafe { RegCloseKey(driver_key) };

        if reg_err != ERROR_SUCCESS {
            log_error(reg_err, "Failed to set SuggestedInstanceId");
            return Err(reg_err);
        }
        Ok(())
    })();

    if !sw_device.is_null() {
        unsafe { SwDeviceClose(sw_device) };
    }
    res
}

struct InstallGuard {
    mutex: HANDLE,
    dev_info: HDEVINFO,
    existing: Vec<SP_DEVINFO_DATA>,
    sw_device: HSWDEVICE,
    completed: bool,
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        if !self.completed && !self.sw_device.is_null() {
            unsafe { SwDeviceClose(self.sw_device) };
        }
        driver_install_deferred_cleanup(self.dev_info, &self.existing);
        namespace_release_mutex(self.mutex);
    }
}

fn open_device_info_for_instance(dev_inst_str: &str) -> Result<(HDEVINFO, SP_DEVINFO_DATA), u32> {
    let dev_info = unsafe {
        SetupDiCreateDeviceInfoListExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if dev_info == INVALID_HDEVINFO || dev_info == 0 {
        return Err(log_last_error("Failed to create adapter device info"));
    }

    let mut dev_info_data = new_dev_info_data();
    let wide_dev_inst = to_wide(dev_inst_str);
    if unsafe {
        SetupDiOpenDeviceInfoW(
            dev_info,
            wide_dev_inst.as_ptr(),
            std::ptr::null_mut(),
            DIOD_INHERIT_CLASSDRVS,
            &mut dev_info_data,
        )
    } == 0
    {
        let err = log_last_error(&format!("Failed to open device instance ID {dev_inst_str}"));
        unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
        return Err(err);
    }
    Ok((dev_info, dev_info_data))
}

fn wintun_create_adapter_inner(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> Result<*mut WintunAdapter, u32> {
    if name.is_null() || tunnel_type.is_null() {
        return Err(ERROR_INVALID_DATA);
    }

    let name_str = unsafe { from_wide_ptr(name) };
    let tunnel_type_str = unsafe { from_wide_ptr(tunnel_type) };

    let mutex = namespace_take_device_installation_mutex()
        .ok_or_else(|| log_last_error("Failed to take device installation mutex"))?;

    let (dev_info_existing, existing_adapters) = match driver_install() {
        Ok(res) => res,
        Err(e) => {
            namespace_release_mutex(mutex);
            return Err(e);
        }
    };

    let mut guard = InstallGuard {
        mutex,
        dev_info: dev_info_existing,
        existing: existing_adapters,
        sw_device: std::ptr::null_mut(),
        completed: false,
    };

    log_msg(WintunLoggerLevel::Info, "Creating adapter");

    let tunnel_type_name = format!("{tunnel_type_str} Tunnel");
    let mut root_node: u32 = 0;
    let mut root_node_name = [0u16; 200];

    let cr1 =
        unsafe { CM_Locate_DevNodeW(&mut root_node, std::ptr::null(), CM_LOCATE_DEVNODE_NORMAL) };
    let cr2 = unsafe {
        CM_Get_Device_IDW(
            root_node,
            root_node_name.as_mut_ptr(),
            root_node_name.len() as u32,
            0,
        )
    };

    if cr1 != CR_SUCCESS || cr2 != CR_SUCCESS {
        let err = unsafe {
            CM_MapCrToWin32Err(if cr1 != CR_SUCCESS { cr1 } else { cr2 }, ERROR_GEN_FAILURE)
        };
        log_error(err, "Failed to get root node name");
        return Err(err);
    }

    let mut instance_guid: GUID = unsafe { std::mem::zeroed() };
    if requested_guid.is_null() {
        let hr = unsafe { CoCreateGuid(&mut instance_guid) };
        if hr < 0 {
            log_error(hr as u32, "Failed to create GUID");
            return Err(hr as u32);
        }
    } else {
        instance_guid = unsafe { *requested_guid };
    }

    let mut instance_id_str = [0u16; 40];
    let str_len = unsafe {
        StringFromGUID2(
            &instance_guid,
            instance_id_str.as_mut_ptr(),
            instance_id_str.len() as i32,
        )
    };
    if str_len == 0 {
        log_msg(WintunLoggerLevel::Err, "Failed to convert GUID");
        return Err(ERROR_GEN_FAILURE);
    }

    let wide_tunnel_name = to_wide(&tunnel_type_name);
    create_stub_device(
        root_node_name.as_ptr(),
        instance_id_str.as_ptr(),
        wide_tunnel_name.as_ptr(),
        &instance_guid,
    )?;

    // Real device creation
    let triggered = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
    if triggered.is_null() {
        return Err(log_last_error("Failed to create event trigger"));
    }

    let mut create_context = SwDeviceCreateContext {
        create_result: 0,
        device_instance_id: [0; MAX_DEVICE_ID_LEN],
        triggered,
    };
    let wintun_hwid_w = to_wide("Wintun");
    let hwids_multi: Vec<u16> = "Wintun\0\0".encode_utf16().collect();
    let real_create_info = SwDeviceCreateInfo::new(
        instance_id_str.as_ptr(),
        hwids_multi.as_ptr(),
        wide_tunnel_name.as_ptr(),
    );
    let wide_name = to_wide(&name_str);

    let real_props = [
        DevProperty::system(
            DEVPKEY_WINTUN_NAME,
            DEVPROP_TYPE_STRING,
            wide_name.as_ptr() as _,
            wide_name.len() * 2,
        ),
        DevProperty::system(
            DEVPKEY_DEVICE_FRIENDLY_NAME,
            DEVPROP_TYPE_STRING,
            wide_tunnel_name.as_ptr() as _,
            wide_tunnel_name.len() * 2,
        ),
        DevProperty::system(
            DEVPKEY_DEVICE_DEVICE_DESC,
            DEVPROP_TYPE_STRING,
            wide_tunnel_name.as_ptr() as _,
            wide_tunnel_name.len() * 2,
        ),
    ];

    let hr2 = unsafe {
        SwDeviceCreate(
            wintun_hwid_w.as_ptr(),
            root_node_name.as_ptr(),
            &real_create_info,
            real_props.len() as u32,
            real_props.as_ptr(),
            device_create_callback,
            &mut create_context as *mut _ as *mut c_void,
            &mut guard.sw_device,
        )
    };

    if hr2 < 0 {
        unsafe { CloseHandle(triggered) };
        log_error(hr2 as u32, "Failed to initiate device creation");
        return Err(hr2 as u32);
    }

    unsafe {
        WaitForSingleObject(triggered, INFINITE);
        CloseHandle(triggered);
    }

    if create_context.create_result < 0 {
        log_error(
            create_context.create_result as u32,
            "Failed to create device",
        );
        return Err(create_context.create_result as u32);
    }

    let dev_inst_str = from_wide_null(&create_context.device_instance_id);
    if !wait_for_interface(&dev_inst_str) {
        let mut last_error =
            diagnose_device_problem(&dev_inst_str).unwrap_or_else(|| unsafe { GetLastError() });
        log_error(last_error, "Failed to setup adapter");
        if last_error == ERROR_SUCCESS {
            last_error = ERROR_DEVICE_NOT_AVAILABLE;
        }
        return Err(last_error);
    }

    let (dev_info, dev_info_data) = open_device_info_for_instance(&dev_inst_str)?;

    let mut adapter = Box::new(WintunAdapter {
        sw_device: guard.sw_device,
        dev_info,
        dev_info_data,
        cfg_instance_id: instance_guid,
        dev_instance_id: create_context.device_instance_id,
        ..Default::default()
    });

    if !populate_adapter_data(&mut adapter) {
        log_msg(WintunLoggerLevel::Err, "Failed to populate adapter data");
        let last_err = unsafe { GetLastError() };
        guard.completed = true;
        wintun_close_adapter(Box::into_raw(adapter));
        return Err(if last_err == ERROR_SUCCESS {
            ERROR_GEN_FAILURE
        } else {
            last_err
        });
    }

    if let Err(e) = nci_set_adapter_name(&adapter.cfg_instance_id, &name_str) {
        log_msg(
            WintunLoggerLevel::Err,
            &format!("Failed to set adapter name \"{}\"", name_str),
        );
        guard.completed = true;
        wintun_close_adapter(Box::into_raw(adapter));
        return Err(e);
    }

    guard.completed = true;
    queue_up_orphaned_device_cleanup_routine();
    Ok(Box::into_raw(adapter))
}

pub fn wintun_create_adapter(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> *mut WintunAdapter {
    match wintun_create_adapter_inner(name, tunnel_type, requested_guid) {
        Ok(ptr) => ptr,
        Err(e) => {
            unsafe { SetLastError(e) };
            std::ptr::null_mut()
        }
    }
}

fn wintun_open_adapter_inner(name_str: &str) -> Result<*mut WintunAdapter, u32> {
    let wintun_enum = to_wide("SWD\\Wintun");
    let dev_info = unsafe {
        SetupDiGetClassDevsExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            wintun_enum.as_ptr(),
            std::ptr::null_mut(),
            DIGCF_PRESENT,
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };

    if dev_info == INVALID_HDEVINFO || dev_info == 0 {
        return Err(log_last_error("Failed to get present adapters"));
    }

    let dev_info_data = enum_device_info(dev_info)
        .find(|data| name_str.eq_ignore_ascii_case(&get_adapter_wintun_name(dev_info, data)))
        .ok_or_else(|| {
            unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
            log_error(ERROR_NOT_FOUND, "Failed to find matching adapter name")
        })?;

    let mut dev_instance_id = [0u16; MAX_DEVICE_ID_LEN];
    let mut req_chars = dev_instance_id.len() as u32;

    if unsafe {
        SetupDiGetDeviceInstanceIdW(
            dev_info,
            &dev_info_data,
            dev_instance_id.as_mut_ptr(),
            req_chars,
            &mut req_chars,
        )
    } == 0
    {
        let err = log_last_error("Failed to get adapter instance ID");
        unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
        return Err(err);
    }

    let dev_inst_str = from_wide_null(&dev_instance_id);

    let mut adapter = Box::new(WintunAdapter {
        dev_info,
        dev_info_data,
        dev_instance_id,
        ..Default::default()
    });

    let ok = wait_for_interface(&dev_inst_str) && populate_adapter_data(&mut adapter);
    adapter.dev_info = 0;
    unsafe { SetupDiDestroyDeviceInfoList(dev_info) };

    if !ok {
        let err = log_last_error("Failed to populate adapter");
        wintun_close_adapter(Box::into_raw(adapter));
        return Err(err);
    }

    Ok(Box::into_raw(adapter))
}

pub fn wintun_open_adapter(name: *const u16) -> *mut WintunAdapter {
    if name.is_null() {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return std::ptr::null_mut();
    }

    let name_str = unsafe { from_wide_ptr(name) };
    let Some(mutex) = namespace_take_device_installation_mutex() else {
        log_last_error("Failed to take device installation mutex");
        return std::ptr::null_mut();
    };

    let res = wintun_open_adapter_inner(&name_str);
    namespace_release_mutex(mutex);
    queue_up_orphaned_device_cleanup_routine();

    match res {
        Ok(ptr) => ptr,
        Err(e) => {
            unsafe { SetLastError(e) };
            std::ptr::null_mut()
        }
    }
}

pub fn wintun_close_adapter(adapter_ptr: *mut WintunAdapter) {
    if adapter_ptr.is_null() {
        return;
    }

    let mut adapter = unsafe { Box::from_raw(adapter_ptr) };

    if !adapter.sw_device.is_null() {
        unsafe {
            SwDeviceClose(adapter.sw_device);
        }
        adapter.sw_device = std::ptr::null_mut();
    }

    if adapter.dev_info != INVALID_HDEVINFO && adapter.dev_info != 0 {
        if !adapter_remove_instance(adapter.dev_info, &mut adapter.dev_info_data) {
            log_last_error("Failed to remove adapter when closing");
        }
        unsafe {
            SetupDiDestroyDeviceInfoList(adapter.dev_info);
        }
        adapter.dev_info = 0;
    }

    drop(adapter);
    queue_up_orphaned_device_cleanup_routine();
}

pub fn wintun_get_adapter_luid(adapter_ptr: *mut WintunAdapter, luid: *mut NetLuid) {
    if adapter_ptr.is_null() || luid.is_null() {
        return;
    }

    let adapter = unsafe { &*adapter_ptr };
    unsafe {
        *luid = NetLuid::new(adapter.luid_index, adapter.if_type);
    }
}
