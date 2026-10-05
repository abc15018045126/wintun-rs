use std::ffi::c_void;
use std::sync::atomic::{AtomicI32, AtomicU32};
pub use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    HDEVINFO, SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
};
pub use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_ITEMS, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
};
pub use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
pub use windows_sys::Win32::System::Registry::RegCloseKey;
pub use windows_sys::core::GUID;

pub type BOOL = i32;
pub type DWORD = u32;
pub type HKEY = *mut c_void;

pub const MAX_PATH: usize = 260;
pub const WINTUN_MIN_RING_CAPACITY: u32 = 0x20000; // 128kiB
pub const WINTUN_MAX_RING_CAPACITY: u32 = 0x4000000; // 64MiB
pub const WINTUN_MAX_IP_PACKET_SIZE: u32 = 0xFFFF; // 65535
pub const ERROR_VERSION_PARSE_ERROR: u32 = 777;
pub const ERROR_INVALID_DATATYPE: u32 = 1804;

#[inline(always)]
pub fn set_last_error(err: u32) {
    unsafe { windows_sys::Win32::Foundation::SetLastError(err) };
}

#[inline(always)]
pub fn get_last_error() -> u32 {
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}

pub const MAX_ADAPTER_NAME: usize = 128;
pub const MAX_DEVICE_ID_LEN: usize = 200;
pub const MAX_REG_PATH: usize = 256;
pub const MAX_GUID_STRING_LEN: usize = 39;
pub const LOCK_SPIN_COUNT: u32 = 0x10000;
pub const TUN_PACKET_RELEASE: u32 = 0x80000000;
pub const TUN_ALIGNMENT: u32 = std::mem::size_of::<u32>() as u32;

pub const INVALID_HDEVINFO: HDEVINFO = -1isize;
pub const FORMAT_MESSAGE_MAX_WIDTH_MASK: u32 = 0x000000FF;

pub const CR_SUCCESS: u32 = 0;
pub const DN_HAS_PROBLEM: u32 = 0x00000400;
pub const CM_PROB_DISABLED: u32 = 22;

pub const WINTUN_HWID: &str = "Wintun";

#[link(name = "cfgmgr32")]
unsafe extern "system" {
    pub fn CM_Get_DevNode_Status(
        pul_status: *mut u32,
        pul_problem_number: *mut u32,
        dn_dev_inst: u32,
        ul_flags: u32,
    ) -> u32;
    pub fn DevCloseObjectQuery(h_dev_query: HDEVQUERY);
}

#[link(name = "shlwapi")]
unsafe extern "system" {
    pub fn PathCombineW(psz_dest: *mut u16, psz_dir: *const u16, psz_file: *const u16) -> *mut u16;
    pub fn PathFindFileNameW(psz_path: *const u16) -> *const u16;
}

#[repr(C)]
pub struct CRITICAL_SECTION {
    pub debug_info: *mut c_void,
    pub lock_count: i32,
    pub recursion_count: i32,
    pub owning_thread: HANDLE,
    pub lock_semaphore: HANDLE,
    pub spin_count: usize,
}

#[repr(C)]
pub struct SP_DRVINFO_DATA_W {
    pub cb_size: u32,
    pub driver_type: u32,
    pub reserved: usize,
    pub description: [u16; 256],
    pub mfg_name: [u16; 256],
    pub provider_name: [u16; 256],
    pub driver_date: FILETIME,
    pub driver_version: u64,
}

impl Default for SP_DRVINFO_DATA_W {
    fn default() -> Self {
        Self {
            cb_size: std::mem::size_of::<Self>() as u32,
            driver_type: 0,
            reserved: 0,
            description: [0; 256],
            mfg_name: [0; 256],
            provider_name: [0; 256],
            driver_date: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            driver_version: 0,
        }
    }
}

#[inline(always)]
pub fn new_dev_info_data() -> SP_DEVINFO_DATA {
    SP_DEVINFO_DATA {
        cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
        ClassGuid: GUID::from_u128(0),
        DevInst: 0,
        Reserved: 0,
    }
}

pub fn enum_device_info(dev_info: HDEVINFO) -> impl Iterator<Item = SP_DEVINFO_DATA> {
    let mut idx = 0;
    std::iter::from_fn(move || {
        loop {
            let mut data = new_dev_info_data();
            if unsafe { SetupDiEnumDeviceInfo(dev_info, idx, &mut data) } == 0 {
                if get_last_error() == ERROR_NO_MORE_ITEMS {
                    return None;
                }
                idx += 1;
                continue;
            }
            idx += 1;
            return Some(data);
        }
    })
}

#[repr(C)]
pub struct SP_DRVINFO_DETAIL_DATA_W {
    pub cb_size: u32,
    pub driver_date: FILETIME,
    pub driver_version: u64,
    pub reserved: u32,
    pub section_name: [u16; 256],
    pub inf_file_name: [u16; 260],
    pub drv_description: [u16; 256],
    pub hardware_id: [u16; 1],
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn InitializeCriticalSectionAndSpinCount(
        lp_critical_section: *mut CRITICAL_SECTION,
        dw_spin_count: u32,
    ) -> BOOL;
    pub fn DeleteCriticalSection(lp_critical_section: *mut CRITICAL_SECTION);
    pub fn EnterCriticalSection(lp_critical_section: *mut CRITICAL_SECTION);
    pub fn LeaveCriticalSection(lp_critical_section: *mut CRITICAL_SECTION);
    pub fn SetEvent(h_event: HANDLE) -> BOOL;
    pub fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    pub fn ReleaseMutex(h_mutex: HANDLE) -> BOOL;
    pub fn GetWindowsDirectoryW(lp_buffer: *mut u16, u_size: u32) -> u32;
    pub fn ExpandEnvironmentStringsW(lp_src: *const u16, lp_dst: *mut u16, n_size: u32) -> u32;
}

pub struct CriticalSectionLock<'a>(&'a mut CRITICAL_SECTION);

impl<'a> CriticalSectionLock<'a> {
    #[inline(always)]
    pub fn new(cs: &'a mut CRITICAL_SECTION) -> Self {
        unsafe { EnterCriticalSection(cs) };
        Self(cs)
    }
}

impl Drop for CriticalSectionLock<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { LeaveCriticalSection(self.0) };
    }
}

#[link(name = "advapi32")]
unsafe extern "system" {
    pub fn OpenProcessToken(
        process_handle: HANDLE,
        desired_access: u32,
        token_handle: *mut HANDLE,
    ) -> BOOL;
}

#[link(name = "ole32")]
unsafe extern "system" {
    pub fn CLSIDFromString(lpsz: *const u16, pclsid: *mut GUID) -> i32;
    pub fn CoCreateGuid(pguid: *mut GUID) -> i32;
    pub fn StringFromGUID2(rguid: *const GUID, lpsz: *mut u16, cch_max: i32) -> i32;
}

#[link(name = "version")]
unsafe extern "system" {
    pub fn GetFileVersionInfoSizeW(lptstr_filename: *const u16, lpdw_handle: *mut u32) -> u32;
    pub fn GetFileVersionInfoW(
        lptstr_filename: *const u16,
        dw_handle: u32,
        dw_len: u32,
        lp_data: *mut c_void,
    ) -> BOOL;
    pub fn VerQueryValueW(
        p_block: *const c_void,
        lp_sub_block: *const u16,
        lplp_buffer: *mut *mut c_void,
        pu_len: *mut u32,
    ) -> BOOL;
}

#[link(name = "setupapi")]
unsafe extern "system" {
    pub fn SetupDiGetDevicePropertyW(
        device_info_set: HDEVINFO,
        device_info_data: *const SP_DEVINFO_DATA,
        property_key: *const DevPropKey,
        property_type: *mut u32,
        property_buffer: *mut u8,
        property_buffer_size: u32,
        required_size: *mut u32,
        flags: u32,
    ) -> BOOL;

    pub fn SetupDiSetDevicePropertyW(
        device_info_set: HDEVINFO,
        device_info_data: *mut SP_DEVINFO_DATA,
        property_key: *const DevPropKey,
        property_type: u32,
        property_buffer: *const u8,
        property_buffer_size: u32,
        flags: u32,
    ) -> BOOL;

    pub fn SetupCopyOEMInfW(
        source_inf_file_name: *const u16,
        oem_source_media_location: *const u16,
        oem_source_media_location_type: u32,
        copy_style: u32,
        destination_inf_file_name: *mut u16,
        destination_inf_file_name_size: u32,
        required_size: *mut u32,
        destination_inf_file_name_component: *mut *mut u16,
    ) -> BOOL;
}

#[inline(always)]
pub const fn tun_align(size: u32) -> u32 {
    (size + (TUN_ALIGNMENT - 1)) & !(TUN_ALIGNMENT - 1)
}

#[inline(always)]
pub const fn tun_is_aligned(size: u32) -> bool {
    (size & (TUN_ALIGNMENT - 1)) == 0
}

pub const TUN_MAX_PACKET_SIZE: u32 =
    tun_align(std::mem::size_of::<TunPacket>() as u32 + WINTUN_MAX_IP_PACKET_SIZE);

#[inline(always)]
pub const fn tun_ring_capacity(size: u32) -> u32 {
    size - std::mem::size_of::<TunRing>() as u32 - (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT)
}

#[inline(always)]
pub const fn tun_ring_size(capacity: u32) -> u32 {
    std::mem::size_of::<TunRing>() as u32 + capacity + (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT)
}

#[inline(always)]
pub const fn tun_ring_wrap(value: u32, capacity: u32) -> u32 {
    value & (capacity - 1)
}

// IOCTL = CTL_CODE(51820U, 0x970U, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
pub const TUN_IOCTL_REGISTER_RINGS: u32 = (51820 << 16) | (3 << 14) | (0x970 << 2);

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WintunLoggerLevel {
    Info = 0,
    Warn = 1,
    Err = 2,
}

pub type WintunLoggerCallback =
    unsafe extern "system" fn(level: WintunLoggerLevel, timestamp: u64, message: *const u16);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DevPropKey {
    pub fmtid: GUID,
    pub pid: u32,
}

pub const fn devpropkey(fmtid: GUID, pid: u32) -> DevPropKey {
    DevPropKey { fmtid, pid }
}

pub const fn guid(d1: u32, d2: u16, d3: u16, d4: u64) -> GUID {
    GUID {
        data1: d1,
        data2: d2,
        data3: d3,
        data4: d4.to_be_bytes(),
    }
}

pub const DEVPROPID_FIRST_USABLE: u32 = 2;

pub const GUID_WINTUN: GUID = guid(0x3361c968, 0x2f2e, 0x4660, 0xb47e699cdc4c32b9);
pub const DEVPKEY_WINTUN_NAME: DevPropKey = devpropkey(GUID_WINTUN, DEVPROPID_FIRST_USABLE + 1);
pub const DEVPKEY_WINTUN_OWNING_PROCESS: DevPropKey =
    devpropkey(GUID_WINTUN, DEVPROPID_FIRST_USABLE + 3);

pub const GUID_DEVCLASS_NET: GUID = guid(0x4d36e972, 0xe325, 0x11ce, 0xbfc108002be10318);
pub const GUID_DEVINTERFACE_NET: GUID = guid(0xcac88484, 0x7515, 0x4c03, 0x82e671a87abac361);

pub const DEVPKEY_DEVICE_INSTANCE_ID: DevPropKey =
    devpropkey(guid(0x78c34fc8, 0x104a, 0x4aca, 0x9ea4524d52996e57), 256);

pub const GUID_DEVINTF: GUID = guid(0x026e516e, 0xb814, 0x414b, 0x83cd856d6fef4822);
pub const DEVPKEY_DEVICE_INTERFACE_ENABLED: DevPropKey = devpropkey(GUID_DEVINTF, 3);
pub const DEVPKEY_DEVICE_INTERFACE_CLASS_GUID: DevPropKey = devpropkey(GUID_DEVINTF, 4);

pub const GUID_DEVPROP: GUID = guid(0xa45c254e, 0xdf1c, 0x4efd, 0x802067d146a850e0);
pub const DEVPKEY_DEVICE_FRIENDLY_NAME: DevPropKey = devpropkey(GUID_DEVPROP, 14);
pub const DEVPKEY_DEVICE_DEVICE_DESC: DevPropKey = devpropkey(GUID_DEVPROP, 2);
pub const DEVPKEY_DEVICE_CLASS_GUID: DevPropKey = devpropkey(GUID_DEVPROP, 10);

pub const GUID_DEVPROBLEM: GUID = guid(0x4340a6c5, 0x93fa, 0x4706, 0x972c7b648008a5a7);
pub const DEVPKEY_DEVICE_PROBLEM_CODE: DevPropKey = devpropkey(GUID_DEVPROBLEM, 3);
pub const DEVPKEY_DEVICE_PROBLEM_STATUS: DevPropKey = devpropkey(GUID_DEVPROBLEM, 12);

pub const DEVPROP_TYPE_STRING: u32 = 0x00000012;
pub const DEVPROP_TYPE_GUID: u32 = 0x0000000D;
pub const DEVPROP_TYPE_BOOLEAN: u32 = 0x00000011;
pub const DEVPROP_TYPE_INT32: u32 = 0x00000006;
pub const DEVPROP_TYPE_UINT32: u32 = 0x00000007;
pub const DEVPROP_TYPE_BINARY: u32 = 0x00000003;
pub const DEVPROP_TYPE_NTSTATUS: u32 = 0x00000018;

pub const DEVPROP_TRUE: i8 = -1;
pub const DEVPROP_STORE_SYSTEM: u32 = 0;

pub const DEVPROP_OPERATOR_EQUALS: u32 = 0x00000002;
pub const DEVPROP_OPERATOR_EQUALS_IGNORE_CASE: u32 = 0x00020002;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DevPropCompKey {
    pub key: DevPropKey,
    pub store: u32,
    pub locale_name: *const u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DevProperty {
    pub comp_key: DevPropCompKey,
    pub prop_type: u32,
    pub buffer_size: u32,
    pub buffer: *mut c_void,
}

impl DevProperty {
    #[inline(always)]
    pub fn system(key: DevPropKey, prop_type: u32, buffer: *const c_void, size: usize) -> Self {
        Self {
            comp_key: DevPropCompKey {
                key,
                store: DEVPROP_STORE_SYSTEM,
                locale_name: std::ptr::null(),
            },
            prop_type,
            buffer_size: size as u32,
            buffer: buffer as *mut _,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DevPropFilterExpression {
    pub operator: u32,
    pub property: DevProperty,
}

impl DevPropFilterExpression {
    #[inline(always)]
    pub fn new(operator: u32, property: DevProperty) -> Self {
        Self { operator, property }
    }
}

pub type HSWDEVICE = *mut c_void;
pub type HDEVQUERY = *mut c_void;

pub const SW_DEVICE_CAPABILITIES_NONE: u32 = 0x00000000;
pub const SW_DEVICE_CAPABILITIES_SILENT_INSTALL: u32 = 0x00000004;
pub const SW_DEVICE_CAPABILITIES_DRIVER_REQUIRED: u32 = 0x00000008;

#[repr(C)]
pub struct SwDeviceCreateInfo {
    pub cb_size: u32,
    pub psz_instance_id: *const u16,
    pub pszz_hardware_ids: *const u16,
    pub pszz_compatible_ids: *const u16,
    pub p_container_id: *const GUID,
    pub capability_flags: u32,
    pub psz_device_description: *const u16,
    pub psz_device_location: *const u16,
    pub p_security_descriptor: *const c_void,
}

impl SwDeviceCreateInfo {
    pub fn new(instance_id: *const u16, hwids: *const u16, description: *const u16) -> Self {
        Self {
            cb_size: std::mem::size_of::<Self>() as u32,
            psz_instance_id: instance_id,
            pszz_hardware_ids: hwids,
            pszz_compatible_ids: std::ptr::null(),
            p_container_id: std::ptr::null(),
            capability_flags: SW_DEVICE_CAPABILITIES_SILENT_INSTALL
                | SW_DEVICE_CAPABILITIES_DRIVER_REQUIRED,
            psz_device_description: description,
            psz_device_location: std::ptr::null(),
            p_security_descriptor: std::ptr::null(),
        }
    }
}

pub type SwDeviceCreateCallback = unsafe extern "system" fn(
    h_sw_device: HSWDEVICE,
    create_result: i32,
    p_context: *mut c_void,
    psz_device_instance_id: *const u16,
);

pub const DEV_OBJECT_TYPE_DEVICE_INTERFACE: u32 = 1;
pub const DEV_QUERY_FLAG_UPDATE_RESULTS: u32 = 0x00000001;

pub const DEV_QUERY_STATE_ABORTED: u32 = 2;

pub const DEV_QUERY_RESULT_STATE_CHANGE: u32 = 0;
pub const DEV_QUERY_RESULT_ADD: u32 = 1;
pub const DEV_QUERY_RESULT_UPDATE: u32 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DevObject {
    pub object_type: u32,
    pub psz_object_id: *const u16,
    pub c_property_count: u32,
    pub p_properties: *const DevProperty,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union DevQueryResultData {
    pub state: u32,
    pub device_object: DevObject,
}

#[repr(C)]
pub struct DevQueryResultActionData {
    pub action: u32,
    pub data: DevQueryResultData,
}

pub type DevQueryCallback = unsafe extern "system" fn(
    h_dev_query: HDEVQUERY,
    p_context: *mut c_void,
    p_action_data: *const DevQueryResultActionData,
);

#[inline(always)]
pub fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct NetLuid {
    pub value: u64,
}

impl NetLuid {
    #[inline(always)]
    pub fn new(net_luid_index: u32, if_type: u32) -> Self {
        let value =
            ((net_luid_index as u64 & 0x00FFFFFF) << 24) | ((if_type as u64 & 0xFFFF) << 48);
        Self { value }
    }

    #[inline(always)]
    pub fn net_luid_index(&self) -> u32 {
        ((self.value >> 24) & 0x00FFFFFF) as u32
    }

    #[inline(always)]
    pub fn if_type(&self) -> u32 {
        ((self.value >> 48) & 0xFFFF) as u32
    }
}

#[repr(C)]
pub struct TunPacket {
    pub size: u32,
}

impl TunPacket {
    #[inline(always)]
    pub unsafe fn data_ptr(ptr: *mut TunPacket) -> *mut u8 {
        (ptr as *mut u8).add(std::mem::size_of::<TunPacket>())
    }

    #[inline(always)]
    pub unsafe fn from_data_ptr(data: *const u8) -> *mut TunPacket {
        (data as *mut u8).sub(std::mem::size_of::<TunPacket>()) as *mut TunPacket
    }
}

#[repr(C)]
pub struct TunRing {
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub alertable: AtomicI32,
}

impl TunRing {
    #[inline(always)]
    pub unsafe fn data_ptr(ptr: *mut TunRing) -> *mut u8 {
        (ptr as *mut u8).add(std::mem::size_of::<TunRing>())
    }
}

pub struct SafeHandle(pub HANDLE);

impl SafeHandle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    #[inline]
    pub fn null() -> Self {
        Self(std::ptr::null_mut())
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut HANDLE {
        &mut self.0
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        self.0.is_null() || self.0 == INVALID_HANDLE_VALUE
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }

    pub fn take(&mut self) -> HANDLE {
        let h = self.0;
        self.0 = std::ptr::null_mut();
        h
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub struct NamespaceMutex(pub HANDLE);

impl NamespaceMutex {
    #[inline]
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    #[inline]
    pub fn raw(&self) -> HANDLE {
        self.0
    }

    #[inline]
    pub fn take(&mut self) -> HANDLE {
        let h = self.0;
        self.0 = std::ptr::null_mut();
        h
    }
}

impl Drop for NamespaceMutex {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }
}

#[inline]
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[inline]
pub fn from_wide_null(slice: &[u16]) -> String {
    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(&slice[..len])
}

#[inline]
pub unsafe fn wide_str_len(ptr: *const u16) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    len
}

#[inline]
pub unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let len = wide_str_len(ptr);
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[inline]
pub fn get_adapter_wintun_name(dev_info: HDEVINFO, dev_info_data: &SP_DEVINFO_DATA) -> String {
    let mut prop_type: u32 = 0;
    let mut name_buf = [0u16; MAX_ADAPTER_NAME];
    let ok = unsafe {
        SetupDiGetDevicePropertyW(
            dev_info,
            dev_info_data,
            &DEVPKEY_WINTUN_NAME,
            &mut prop_type,
            name_buf.as_mut_ptr() as _,
            (MAX_ADAPTER_NAME * 2) as u32,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 || name_buf[0] == 0 {
        "<unknown>".to_string()
    } else {
        from_wide_null(&name_buf)
    }
}

unsafe extern "C" {
    fn _wcsicmp(string1: *const u16, string2: *const u16) -> i32;
}

#[inline]
pub unsafe fn wide_eq_ignore_case(a: *const u16, b: *const u16) -> bool {
    if a.is_null() || b.is_null() {
        return a == b;
    }
    _wcsicmp(a, b) == 0
}

pub fn adapter_has_wintun_name(
    dev_info: HDEVINFO,
    dev_info_data: &SP_DEVINFO_DATA,
    expected_name: *const u16,
) -> bool {
    let mut prop_type: u32 = 0;
    let mut name_buf = [0u16; MAX_ADAPTER_NAME];
    let ok = unsafe {
        SetupDiGetDevicePropertyW(
            dev_info,
            dev_info_data,
            &DEVPKEY_WINTUN_NAME,
            &mut prop_type,
            name_buf.as_mut_ptr() as _,
            (MAX_ADAPTER_NAME * 2) as u32,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 || prop_type != DEVPROP_TYPE_STRING {
        return false;
    }
    unsafe { wide_eq_ignore_case(name_buf.as_ptr(), expected_name) }
}

pub struct SafeVirtualAlloc {
    ptr: *mut u8,
}

impl SafeVirtualAlloc {
    pub fn new(ptr: *mut u8) -> Self {
        Self { ptr }
    }

    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn take(&mut self) -> *mut u8 {
        let p = self.ptr;
        self.ptr = std::ptr::null_mut();
        p
    }
}

impl Drop for SafeVirtualAlloc {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { VirtualFree(self.ptr as _, 0, MEM_RELEASE) };
        }
    }
}

pub struct DeviceInfoSet(pub HDEVINFO);

impl DeviceInfoSet {
    #[inline]
    pub fn new(handle: HDEVINFO) -> Self {
        Self(handle)
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        self.0 == INVALID_HDEVINFO || self.0 == 0
    }

    #[inline]
    pub fn raw(&self) -> HDEVINFO {
        self.0
    }

    #[inline]
    pub fn take(&mut self) -> HDEVINFO {
        let h = self.0;
        self.0 = 0;
        h
    }
}

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        if self.0 != INVALID_HDEVINFO && self.0 != 0 {
            unsafe { SetupDiDestroyDeviceInfoList(self.0) };
        }
    }
}

pub struct DevQuery(pub HDEVQUERY);

impl DevQuery {
    #[inline]
    pub fn new(h: HDEVQUERY) -> Self {
        Self(h)
    }

    #[inline]
    pub fn raw(&self) -> HDEVQUERY {
        self.0
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn as_mut_raw(&mut self) -> *mut HDEVQUERY {
        &mut self.0
    }
}

impl Drop for DevQuery {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { DevCloseObjectQuery(self.0) };
        }
    }
}

pub struct RegKey(pub HKEY);

impl RegKey {
    #[inline]
    pub fn new(key: HKEY) -> Self {
        Self(key)
    }

    #[inline]
    pub fn raw(&self) -> HKEY {
        self.0
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn take(&mut self) -> HKEY {
        let k = self.0;
        self.0 = std::ptr::null_mut();
        k
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { RegCloseKey(self.0) };
        }
    }
}

#[repr(C)]
pub struct TunRingDescriptor {
    pub ring_size: u32,
    pub ring: *mut TunRing,
    pub tail_moved: HANDLE,
}

#[repr(C)]
pub struct TunRegisterRings {
    pub send: TunRingDescriptor,
    pub receive: TunRingDescriptor,
}

pub struct SessionReceiveState {
    pub tail: u32,
    pub tail_release: u32,
    pub packets_to_release: u32,
    pub lock: CRITICAL_SECTION,
}

impl Default for SessionReceiveState {
    fn default() -> Self {
        Self {
            tail: 0,
            tail_release: 0,
            packets_to_release: 0,
            lock: unsafe { std::mem::zeroed() },
        }
    }
}

pub struct SessionSendState {
    pub head: u32,
    pub head_release: u32,
    pub packets_to_release: u32,
    pub lock: CRITICAL_SECTION,
}

impl Default for SessionSendState {
    fn default() -> Self {
        Self {
            head: 0,
            head_release: 0,
            packets_to_release: 0,
            lock: unsafe { std::mem::zeroed() },
        }
    }
}

pub struct TunSession {
    pub capacity: u32,
    pub receive: SessionReceiveState,
    pub send: SessionSendState,
    pub descriptor: TunRegisterRings,
    pub handle: HANDLE,
    pub allocated_region: *mut u8,
}

impl Drop for TunSession {
    fn drop(&mut self) {
        unsafe {
            DeleteCriticalSection(&mut self.send.lock);
            DeleteCriticalSection(&mut self.receive.lock);
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
                CloseHandle(self.handle);
            }
            if !self.descriptor.send.tail_moved.is_null() {
                CloseHandle(self.descriptor.send.tail_moved);
            }
            if !self.descriptor.receive.tail_moved.is_null() {
                CloseHandle(self.descriptor.receive.tail_moved);
            }
            if !self.allocated_region.is_null() {
                VirtualFree(self.allocated_region as _, 0, MEM_RELEASE);
            }
        }
    }
}

pub struct WintunAdapter {
    pub sw_device: HSWDEVICE,
    pub dev_info: HDEVINFO,
    pub dev_info_data: SP_DEVINFO_DATA,
    pub interface_filename: Vec<u16>,
    pub cfg_instance_id: GUID,
    pub dev_instance_id: [u16; MAX_DEVICE_ID_LEN],
    pub luid_index: u32,
    pub if_type: u32,
    pub if_index: u32,
}

impl Default for WintunAdapter {
    fn default() -> Self {
        Self {
            sw_device: std::ptr::null_mut(),
            dev_info: 0,
            dev_info_data: new_dev_info_data(),
            interface_filename: Vec::new(),
            cfg_instance_id: GUID::from_u128(0),
            dev_instance_id: [0; MAX_DEVICE_ID_LEN],
            luid_index: 0,
            if_type: 0,
            if_index: 0,
        }
    }
}

#[allow(non_camel_case_types)]
pub type WINTUN_ADAPTER_HANDLE = *mut WintunAdapter;
#[allow(non_camel_case_types)]
pub type WINTUN_SESSION_HANDLE = *mut TunSession;
