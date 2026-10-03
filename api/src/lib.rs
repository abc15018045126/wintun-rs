#![allow(
    clippy::missing_safety_doc,
    clippy::too_many_arguments,
    clippy::not_unsafe_ptr_arg_deref,
    unsafe_op_in_unsafe_fn
)]

pub mod adapter;
pub mod driver;
pub mod logger;
pub mod namespace;
pub mod nci;
pub mod ntdll;
pub mod registry;
pub mod resource;
pub mod safe;
pub mod session;
pub mod types;

pub use safe::{ensure_initialized, Adapter, Packet, SendPacket, Session};

#[cfg(test)]
mod tests;

use std::ffi::c_void;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{HANDLE, HINSTANCE};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

use crate::types::*;

const TRUE: BOOL = 1;

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            if !namespace::init_security_objects() {
                return 0;
            }
            adapter::adapter_cleanup_legacy_devices();
        }
        DLL_PROCESS_DETACH => {
            namespace::namespace_done();
        }
        _ => {}
    };
    TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunCreateAdapter(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> WINTUN_ADAPTER_HANDLE {
    adapter::wintun_create_adapter(name, tunnel_type, requested_guid)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunOpenAdapter(name: *const u16) -> WINTUN_ADAPTER_HANDLE {
    adapter::wintun_open_adapter(name)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunCloseAdapter(adapter: WINTUN_ADAPTER_HANDLE) {
    adapter::wintun_close_adapter(adapter)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunDeleteDriver() -> BOOL {
    if driver::wintun_delete_driver() {
        TRUE
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunGetAdapterLUID(
    adapter: WINTUN_ADAPTER_HANDLE,
    luid: *mut NetLuid,
) {
    adapter::wintun_get_adapter_luid(adapter, luid)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunGetRunningDriverVersion() -> DWORD {
    driver::wintun_get_running_driver_version()
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunSetLogger(new_logger: Option<WintunLoggerCallback>) {
    logger::set_logger(new_logger)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunStartSession(
    adapter: WINTUN_ADAPTER_HANDLE,
    capacity: DWORD,
) -> WINTUN_SESSION_HANDLE {
    session::wintun_start_session(adapter, capacity)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunEndSession(session: WINTUN_SESSION_HANDLE) {
    session::wintun_end_session(session)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunGetReadWaitEvent(session: WINTUN_SESSION_HANDLE) -> HANDLE {
    session::wintun_get_read_wait_event(session)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunReceivePacket(
    session: WINTUN_SESSION_HANDLE,
    packet_size: *mut DWORD,
) -> *mut u8 {
    session::wintun_receive_packet(session, packet_size)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunReleaseReceivePacket(
    session: WINTUN_SESSION_HANDLE,
    packet: *const u8,
) {
    session::wintun_release_receive_packet(session, packet)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunAllocateSendPacket(
    session: WINTUN_SESSION_HANDLE,
    packet_size: DWORD,
) -> *mut u8 {
    session::wintun_allocate_send_packet(session, packet_size)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn WintunSendPacket(session: WINTUN_SESSION_HANDLE, packet: *const u8) {
    session::wintun_send_packet(session, packet)
}
