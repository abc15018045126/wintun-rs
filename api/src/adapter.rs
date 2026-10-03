use crate::ntdll::RtlNtStatusToDosError;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_DEVICE_NOT_AVAILABLE, ERROR_GEN_FAILURE, ERROR_INVALID_DATA,
    ERROR_NOT_FOUND, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
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
use windows_sys::Win32::System::Registry::{RegSetValueExW, REG_BINARY};
use windows_sys::Win32::System::Threading::{
    CreateEventW, QueueUserWorkItem, SetEvent, WaitForSingleObject, INFINITE,
};

use crate::driver::{driver_install, driver_install_deferred_cleanup};
use crate::logger::{get_registry_key_path, is_logger_active, log_error, log_last_error, log_msg};
use crate::namespace::namespace_take_device_installation_mutex;
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

fn wait_for_interface(wide_instance: *const u16) -> bool {
    let instance_len = (0..MAX_DEVICE_ID_LEN)
        .position(|i| unsafe { *wide_instance.add(i) } == 0)
        .unwrap_or(MAX_DEVICE_ID_LEN);
    let dev_prop_true: i8 = DEVPROP_TRUE;

    let filters = [
        DevPropFilterExpression::new(
            DEVPROP_OPERATOR_EQUALS_IGNORE_CASE,
            DevProperty::system(
                DEVPKEY_DEVICE_INSTANCE_ID,
                DEVPROP_TYPE_STRING,
                wide_instance as _,
                (instance_len + 1) * 2,
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

    let event =
        SafeHandle::new(unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) });
    if event.is_invalid() {
        log_last_error("Failed to create event");
        return false;
    }

    let mut ctx = WaitForInterfaceCtx {
        event: event.raw(),
        last_error: ERROR_SUCCESS,
    };

    let mut query = DevQuery::new(std::ptr::null_mut());
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
            query.as_mut_raw(),
        )
    };

    if hr < 0 {
        log_error(hr as u32, "Failed to create device query");
        set_last_error(hr as u32);
        return false;
    }

    let wait_res = unsafe { WaitForSingleObject(event.raw(), 15000) };
    let last_error = if wait_res != WAIT_OBJECT_0 {
        if wait_res == WAIT_FAILED {
            log_last_error("Failed to wait for device query")
        } else {
            log_error(wait_res, "Timed out waiting for device query")
        }
    } else {
        let err = ctx.last_error;
        if err != ERROR_SUCCESS {
            log_error(err, "Failed to get enabled device")
        } else {
            ERROR_SUCCESS
        }
    };

    drop(query);
    drop(event);

    if last_error != ERROR_SUCCESS {
        set_last_error(last_error);
        false
    } else {
        true
    }
}

pub fn adapter_get_device_object_file_name(wide_instance: *const u16) -> Result<Vec<u16>, u32> {
    let mut interfaces_len: u32 = 0;
    let cr = unsafe {
        CM_Get_Device_Interface_List_SizeW(
            &mut interfaces_len,
            &GUID_DEVINTERFACE_NET,
            wide_instance,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        )
    };
    let last_error = unsafe { CM_MapCrToWin32Err(cr, ERROR_GEN_FAILURE) };
    if last_error != ERROR_SUCCESS {
        if is_logger_active() {
            let instance_str = unsafe { from_wide_ptr(wide_instance) };
            log_error(
                last_error,
                &format!(
                    "Failed to query adapter {} associated instances size",
                    instance_str
                ),
            );
        }
        set_last_error(last_error);
        return Err(last_error);
    }

    let mut interfaces = vec![0u16; interfaces_len as usize];
    let cr2 = unsafe {
        CM_Get_Device_Interface_ListW(
            &GUID_DEVINTERFACE_NET,
            wide_instance,
            interfaces.as_mut_ptr(),
            interfaces_len,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        )
    };
    let last_error2 = unsafe { CM_MapCrToWin32Err(cr2, ERROR_GEN_FAILURE) };
    if last_error2 != ERROR_SUCCESS {
        if is_logger_active() {
            let instance_str = unsafe { from_wide_ptr(wide_instance) };
            log_error(
                last_error2,
                &format!(
                    "Failed to get adapter {} associated instances",
                    instance_str
                ),
            );
        }
        set_last_error(last_error2);
        return Err(last_error2);
    }

    if interfaces.is_empty() || interfaces[0] == 0 {
        set_last_error(ERROR_DEVICE_NOT_AVAILABLE);
        return Err(ERROR_DEVICE_NOT_AVAILABLE);
    }

    Ok(interfaces)
}

fn populate_adapter_data(adapter: &mut WintunAdapter) -> bool {
    let last_error;

    let raw_key = unsafe {
        SetupDiOpenDevRegKey(
            adapter.dev_info,
            &adapter.dev_info_data,
            DICS_FLAG_GLOBAL,
            0,
            DIREG_DRV,
            windows_sys::Win32::System::Registry::KEY_QUERY_VALUE,
        )
    };

    if raw_key.is_null() || std::ptr::eq(raw_key, INVALID_HANDLE_VALUE as HKEY) {
        log_last_error("Failed to open adapter device registry key");
        return false;
    }

    let key = RegKey::new(raw_key);

    let value_str = match registry_query_string(raw_key, windows_sys::w!("NetCfgInstanceId"), true)
    {
        Ok(s) => s,
        Err(_) => {
            let reg_path = get_registry_key_path(raw_key);
            last_error = log_msg(
                WintunLoggerLevel::Err,
                &format!("Failed to get {}\\NetCfgInstanceId", reg_path),
            );
            drop(key);
            set_last_error(last_error);
            return false;
        }
    };

    let hr = unsafe { CLSIDFromString(value_str.as_ptr(), &mut adapter.cfg_instance_id) };
    if hr < 0 {
        let reg_path = get_registry_key_path(raw_key);
        let val_display = unsafe { from_wide_ptr(value_str.as_ptr()) };
        last_error = log_msg(
            WintunLoggerLevel::Err,
            &format!(
                "{}\\NetCfgInstanceId is not a GUID: {}",
                reg_path, val_display
            ),
        );
        drop(key);
        set_last_error(last_error);
        return false;
    }

    match registry_query_dword(raw_key, windows_sys::w!("NetLuidIndex"), true) {
        Ok(val) => adapter.luid_index = val,
        Err(_) => {
            let reg_path = get_registry_key_path(raw_key);
            last_error = log_msg(
                WintunLoggerLevel::Err,
                &format!("Failed to get {}\\NetLuidIndex", reg_path),
            );
            drop(key);
            set_last_error(last_error);
            return false;
        }
    }

    match registry_query_dword(raw_key, windows_sys::w!("*IfType"), true) {
        Ok(val) => adapter.if_type = val,
        Err(_) => {
            let reg_path = get_registry_key_path(raw_key);
            last_error = log_msg(
                WintunLoggerLevel::Err,
                &format!("Failed to get {}\\*IfType", reg_path),
            );
            drop(key);
            set_last_error(last_error);
            return false;
        }
    }

    drop(key);

    let filename = match adapter_get_device_object_file_name(adapter.dev_instance_id.as_ptr()) {
        Ok(f) => f,
        Err(_) => {
            last_error = log_last_error("Unable to determine device object file name");
            set_last_error(last_error);
            return false;
        }
    };

    adapter.interface_filename = filename;
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
    let Some(_mutex) = namespace_take_device_installation_mutex() else {
        log_last_error("Failed to take device installation mutex");
        return;
    };

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
        log_last_error("Failed to get adapters");
        return;
    }

    for mut dev_info_data in enum_device_info(dev_info.raw()) {
        let mut status: u32 = 0;
        let mut code: u32 = 0;
        if unsafe { CM_Get_DevNode_Status(&mut status, &mut code, dev_info_data.DevInst, 0) }
            == CR_SUCCESS
            && (status & DN_HAS_PROBLEM) == 0
        {
            continue;
        }

        let name = get_adapter_wintun_name(dev_info.raw(), &dev_info_data);
        if !adapter_remove_instance(dev_info.raw(), &mut dev_info_data) {
            log_last_error(&format!("Failed to remove orphaned adapter \"{}\"", name));
            continue;
        }
        log_msg(
            WintunLoggerLevel::Info,
            &format!("Removed orphaned adapter \"{}\"", name),
        );
    }
}

pub fn adapter_cleanup_legacy_devices() {
    let dev_info = DeviceInfoSet::new(unsafe {
        SetupDiGetClassDevsExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            windows_sys::w!("ROOT\\NET"),
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    });

    if dev_info.is_invalid() {
        return;
    }

    for mut dev_info_data in enum_device_info(dev_info.raw()) {
        let mut hwid_buf = [0u16; 1024];
        let mut val_type: u32 = 0;
        let mut size = (hwid_buf.len() * std::mem::size_of::<u16>()) as u32;

        if unsafe {
            windows_sys::Win32::Devices::DeviceAndDriverInstallation::SetupDiGetDeviceRegistryPropertyW(
                dev_info.raw(),
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
        let mut offset = 0;
        while offset < slice.len() {
            let p = &slice[offset..];
            if p[0] == 0 {
                break;
            }
            let len = p.iter().position(|&c| c == 0).unwrap_or(p.len());
            let item = &p[..len];
            if unsafe { wide_eq_ignore_case(item.as_ptr(), windows_sys::w!("Wintun")) } {
                adapter_remove_instance(dev_info.raw(), &mut dev_info_data);
                break;
            }
            offset += len + 1;
        }
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

    if handle == INVALID_HANDLE_VALUE && is_logger_active() {
        let name_str = unsafe { from_wide_ptr(adapter.interface_filename.as_ptr()) };
        log_last_error(&format!(
            "Failed to connect to adapter interface {}",
            name_str
        ));
    }
    handle
}

fn diagnose_device_problem(wide_inst: *const u16) -> u32 {
    let mut last_error = get_last_error();
    let diag_dev_info = DeviceInfoSet::new(unsafe {
        SetupDiCreateDeviceInfoListExW(
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    });
    if diag_dev_info.is_invalid() {
        return last_error;
    }
    let mut diag_data = new_dev_info_data();
    if unsafe {
        SetupDiOpenDeviceInfoW(
            diag_dev_info.raw(),
            wide_inst,
            std::ptr::null_mut(),
            DIOD_INHERIT_CLASSDRVS,
            &mut diag_data,
        )
    } == 0
    {
        return last_error;
    }

    let mut prop_type = 0;
    let mut nt_status: i32 = 0;
    let mut problem_code: u32 = 0;
    let mut size = std::mem::size_of::<i32>() as u32;

    let status_ok = unsafe {
        SetupDiGetDevicePropertyW(
            diag_dev_info.raw(),
            &diag_data,
            &DEVPKEY_DEVICE_PROBLEM_STATUS,
            &mut prop_type,
            &mut nt_status as *mut _ as _,
            size,
            &mut size,
            0,
        )
    };
    if status_ok == 0 || prop_type != DEVPROP_TYPE_NTSTATUS {
        nt_status = 0;
    }

    size = std::mem::size_of::<u32>() as u32;
    let code_ok = unsafe {
        SetupDiGetDevicePropertyW(
            diag_dev_info.raw(),
            &diag_data,
            &DEVPKEY_DEVICE_PROBLEM_CODE,
            &mut prop_type,
            &mut problem_code as *mut _ as _,
            size,
            &mut size,
            0,
        )
    };
    if code_ok == 0 || (prop_type != DEVPROP_TYPE_INT32 && prop_type != DEVPROP_TYPE_UINT32) {
        problem_code = 0;
    }

    last_error = unsafe { RtlNtStatusToDosError(nt_status) };
    if last_error == ERROR_SUCCESS {
        last_error = ERROR_DEVICE_NOT_AVAILABLE;
    }
    log_error(
        last_error,
        &format!(
            "Failed to setup adapter (problem code: 0x{:X}, ntstatus: 0x{:X})",
            problem_code, nt_status as u32
        ),
    );
    last_error
}

fn create_stub_device(
    root_node_name: *const u16,
    instance_id_str: *const u16,
    wide_tunnel_name: *const u16,
    instance_guid: &GUID,
) -> Result<(), u32> {
    let triggered =
        SafeHandle::new(unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) });
    if triggered.is_invalid() {
        return Err(log_last_error("Failed to create event trigger"));
    }

    let mut create_context = SwDeviceCreateContext {
        create_result: 0,
        device_instance_id: [0; MAX_DEVICE_ID_LEN],
        triggered: triggered.raw(),
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

    let wintun_hwid_w = windows_sys::w!("Wintun");
    let hr = unsafe {
        SwDeviceCreate(
            wintun_hwid_w,
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
        log_error(hr as u32, "Failed to initiate stub device creation");
        return Err(hr as u32);
    }

    let wait_res = unsafe { WaitForSingleObject(triggered.raw(), INFINITE) };
    if wait_res != WAIT_OBJECT_0 {
        let last_error = log_last_error("Failed to wait for stub device creation trigger");
        if !sw_device.is_null() {
            unsafe { SwDeviceClose(sw_device) };
        }
        return Err(last_error);
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

        let mut driver_key_raw: HKEY = std::ptr::null_mut();
        let cr_key = unsafe {
            CM_Open_DevNode_Key(
                dev_inst,
                windows_sys::Win32::System::Registry::KEY_SET_VALUE,
                0,
                REG_DISPOSITION_OPEN_ALWAYS,
                &mut driver_key_raw,
                CM_REGISTRY_SOFTWARE,
            )
        };
        if cr_key != CR_SUCCESS {
            let err = unsafe { CM_MapCrToWin32Err(cr_key, ERROR_PNP_REGISTRY_ERROR) };
            log_error(err, "Failed to create software registry key");
            return Err(err);
        }
        let driver_key = RegKey::new(driver_key_raw);

        let suggested_id_w = windows_sys::w!("SuggestedInstanceId");
        let reg_err = unsafe {
            RegSetValueExW(
                driver_key.raw(),
                suggested_id_w,
                0,
                REG_BINARY,
                instance_guid as *const _ as *const u8,
                std::mem::size_of::<GUID>() as u32,
            )
        };

        if reg_err != ERROR_SUCCESS {
            let id_str = unsafe { from_wide_ptr(instance_id_str) };
            log_error(
                reg_err,
                &format!("Failed to set SuggestedInstanceId to {}", id_str),
            );
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
    _mutex: NamespaceMutex,
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
    }
}

fn open_device_info_for_instance(
    wide_dev_inst: *const u16,
) -> Result<(HDEVINFO, SP_DEVINFO_DATA), u32> {
    let mut dev_info = DeviceInfoSet::new(unsafe {
        SetupDiCreateDeviceInfoListExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    });
    if dev_info.is_invalid() {
        return Err(log_last_error("Failed to make device list"));
    }

    let mut dev_info_data = new_dev_info_data();
    if unsafe {
        SetupDiOpenDeviceInfoW(
            dev_info.raw(),
            wide_dev_inst,
            std::ptr::null_mut(),
            DIOD_INHERIT_CLASSDRVS,
            &mut dev_info_data,
        )
    } == 0
    {
        if is_logger_active() {
            let id_str = unsafe { from_wide_ptr(wide_dev_inst) };
            log_last_error(&format!("Failed to open device instance ID {id_str}"));
        }
        return Err(get_last_error());
    }
    Ok((dev_info.take(), dev_info_data))
}

fn wintun_create_adapter_inner(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> Result<*mut WintunAdapter, u32> {
    if name.is_null() || tunnel_type.is_null() {
        return Err(ERROR_INVALID_DATA);
    }

    let mutex = namespace_take_device_installation_mutex()
        .ok_or_else(|| log_last_error("Failed to take device installation mutex"))?;

    let (dev_info_existing, existing_adapters) = driver_install()?;

    let mut guard = InstallGuard {
        _mutex: mutex,
        dev_info: dev_info_existing,
        existing: existing_adapters,
        sw_device: std::ptr::null_mut(),
        completed: false,
    };

    log_msg(WintunLoggerLevel::Info, "Creating adapter");

    let mut wide_tunnel_name = [0u16; MAX_ADAPTER_NAME + 8];
    let mut t_len = 0;
    unsafe {
        while *tunnel_type.add(t_len) != 0 {
            if t_len >= MAX_ADAPTER_NAME {
                set_last_error(ERROR_BUFFER_OVERFLOW);
                return Err(ERROR_BUFFER_OVERFLOW);
            }
            wide_tunnel_name[t_len] = *tunnel_type.add(t_len);
            t_len += 1;
        }
    }
    const TUNNEL_SUFFIX: [u16; 7] = [0x0020, 0x0054, 0x0075, 0x006E, 0x006E, 0x0065, 0x006C]; // " Tunnel"
    wide_tunnel_name[t_len..t_len + TUNNEL_SUFFIX.len()].copy_from_slice(&TUNNEL_SUFFIX);
    t_len += TUNNEL_SUFFIX.len();
    wide_tunnel_name[t_len] = 0;
    let total_tunnel_chars = t_len + 1;

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

    let mut instance_guid = GUID::from_u128(0);
    let mut h_ret: i32 = 0;
    if requested_guid.is_null() {
        h_ret = unsafe { CoCreateGuid(&mut instance_guid) };
    } else {
        instance_guid = unsafe { *requested_guid };
    }

    let mut instance_id_str = [0u16; MAX_GUID_STRING_LEN];
    let str_len = if h_ret >= 0 {
        unsafe {
            StringFromGUID2(
                &instance_guid,
                instance_id_str.as_mut_ptr(),
                instance_id_str.len() as i32,
            )
        }
    } else {
        0
    };
    if h_ret < 0 || str_len == 0 {
        let err = h_ret as u32;
        log_error(err, "Failed to convert GUID");
        return Err(err);
    }

    create_stub_device(
        root_node_name.as_ptr(),
        instance_id_str.as_ptr(),
        wide_tunnel_name.as_ptr(),
        &instance_guid,
    )?;

    // Real device creation
    let triggered =
        SafeHandle::new(unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) });
    if triggered.is_invalid() {
        return Err(log_last_error("Failed to create event trigger"));
    }

    let mut create_context = SwDeviceCreateContext {
        create_result: 0,
        device_instance_id: [0; MAX_DEVICE_ID_LEN],
        triggered: triggered.raw(),
    };
    let wintun_hwid_w = windows_sys::w!("Wintun");
    let hwids_multi = windows_sys::w!("Wintun\0");
    let real_create_info = SwDeviceCreateInfo::new(
        instance_id_str.as_ptr(),
        hwids_multi,
        wide_tunnel_name.as_ptr(),
    );
    let name_len = (0..MAX_ADAPTER_NAME)
        .position(|i| unsafe { *name.add(i) } == 0)
        .unwrap_or(0);

    let real_props = [
        DevProperty::system(
            DEVPKEY_WINTUN_NAME,
            DEVPROP_TYPE_STRING,
            name as _,
            (name_len + 1) * 2,
        ),
        DevProperty::system(
            DEVPKEY_DEVICE_FRIENDLY_NAME,
            DEVPROP_TYPE_STRING,
            wide_tunnel_name.as_ptr() as _,
            total_tunnel_chars * 2,
        ),
        DevProperty::system(
            DEVPKEY_DEVICE_DEVICE_DESC,
            DEVPROP_TYPE_STRING,
            wide_tunnel_name.as_ptr() as _,
            total_tunnel_chars * 2,
        ),
    ];

    let hr2 = unsafe {
        SwDeviceCreate(
            wintun_hwid_w,
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
        log_error(hr2 as u32, "Failed to initiate device creation");
        return Err(hr2 as u32);
    }

    let wait_res = unsafe { WaitForSingleObject(triggered.raw(), INFINITE) };
    if wait_res != WAIT_OBJECT_0 {
        let last_error = log_last_error("Failed to wait for device creation trigger");
        return Err(last_error);
    }

    if create_context.create_result < 0 {
        log_error(
            create_context.create_result as u32,
            "Failed to create device",
        );
        return Err(create_context.create_result as u32);
    }

    if !wait_for_interface(create_context.device_instance_id.as_ptr()) {
        let last_error = diagnose_device_problem(create_context.device_instance_id.as_ptr());
        return Err(last_error);
    }

    let (dev_info, dev_info_data) =
        open_device_info_for_instance(create_context.device_instance_id.as_ptr())?;

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
        let last_err = get_last_error();
        guard.completed = true;
        wintun_close_adapter(Box::into_raw(adapter));
        return Err(if last_err == ERROR_SUCCESS {
            ERROR_GEN_FAILURE
        } else {
            last_err
        });
    }

    if let Err(e) = nci_set_adapter_name(&adapter.cfg_instance_id, name) {
        let name_str = unsafe { from_wide_ptr(name) };
        log_msg(
            WintunLoggerLevel::Err,
            &format!("Failed to set adapter name \"{}\"", name_str),
        );
        guard.completed = true;
        wintun_close_adapter(Box::into_raw(adapter));
        return Err(e);
    }

    guard.completed = true;
    Ok(Box::into_raw(adapter))
}

pub fn wintun_create_adapter(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> *mut WintunAdapter {
    let res = wintun_create_adapter_inner(name, tunnel_type, requested_guid);
    queue_up_orphaned_device_cleanup_routine();
    match res {
        Ok(ptr) => ptr,
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

fn wintun_open_adapter_inner(name: *const u16) -> Result<*mut WintunAdapter, u32> {
    let dev_info = DeviceInfoSet::new(unsafe {
        SetupDiGetClassDevsExW(
            &GUID_DEVCLASS_NET as *const _ as *const _,
            windows_sys::w!("SWD\\Wintun"),
            std::ptr::null_mut(),
            DIGCF_PRESENT,
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    });

    if dev_info.is_invalid() {
        return Err(log_last_error("Failed to get present adapters"));
    }

    let dev_info_data = enum_device_info(dev_info.raw())
        .find(|data| adapter_has_wintun_name(dev_info.raw(), data, name))
        .ok_or_else(|| log_error(ERROR_NOT_FOUND, "Failed to find matching adapter name"))?;

    let mut dev_instance_id = [0u16; MAX_DEVICE_ID_LEN];
    let mut req_chars = dev_instance_id.len() as u32;

    if unsafe {
        SetupDiGetDeviceInstanceIdW(
            dev_info.raw(),
            &dev_info_data,
            dev_instance_id.as_mut_ptr(),
            req_chars,
            &mut req_chars,
        )
    } == 0
    {
        return Err(log_last_error("Failed to get adapter instance ID"));
    }

    let mut adapter = Box::new(WintunAdapter {
        dev_info: dev_info.raw(),
        dev_info_data,
        dev_instance_id,
        ..Default::default()
    });

    let ok = wait_for_interface(dev_instance_id.as_ptr()) && populate_adapter_data(&mut adapter);
    adapter.dev_info = 0;

    if !ok {
        let err = log_last_error("Failed to populate adapter");
        wintun_close_adapter(Box::into_raw(adapter));
        return Err(err);
    }

    Ok(Box::into_raw(adapter))
}

pub fn wintun_open_adapter(name: *const u16) -> *mut WintunAdapter {
    if name.is_null() {
        set_last_error(ERROR_INVALID_DATA);
        return std::ptr::null_mut();
    }

    let Some(_mutex) = namespace_take_device_installation_mutex() else {
        let last_error = log_last_error("Failed to take device installation mutex");
        queue_up_orphaned_device_cleanup_routine();
        set_last_error(last_error);
        return std::ptr::null_mut();
    };

    let res = wintun_open_adapter_inner(name);
    drop(_mutex);
    queue_up_orphaned_device_cleanup_routine();

    match res {
        Ok(ptr) => ptr,
        Err(e) => {
            set_last_error(e);
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
