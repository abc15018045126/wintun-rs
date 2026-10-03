use std::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

pub const SYSTEM_MODULE_INFORMATION: u32 = 11;
pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004_u32 as NTSTATUS;
pub const STATUS_SUCCESS: NTSTATUS = 0;

#[repr(C)]
pub struct RtlProcessModuleInformation {
    pub section: HANDLE,
    pub mapped_base: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u32,
    pub flags: u32,
    pub load_order_index: u16,
    pub init_order_index: u16,
    pub load_count: u16,
    pub offset_to_file_name: u16,
    pub full_path_name: [u8; 256],
}

#[repr(C)]
pub struct RtlProcessModules {
    pub number_of_modules: u32,
    pub modules: [RtlProcessModuleInformation; 1],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtQuerySystemInformation(
        class: u32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> NTSTATUS;
    pub fn NtQuerySystemTime(time: *mut i64) -> NTSTATUS;
    pub fn RtlNtStatusToDosError(status: NTSTATUS) -> u32;
    pub fn NtQueryKey(
        key: HANDLE,
        class: i32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> NTSTATUS;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    #[link_name = "SystemFunction036"]
    pub fn RtlGenRandom(buf: *mut c_void, len: u32) -> u8;
}
