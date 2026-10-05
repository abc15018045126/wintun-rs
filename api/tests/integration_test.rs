use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD, FreeLibrary, GetLastError, HMODULE,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::core::GUID;

type WintunCreateAdapterFn = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> *mut c_void;

type WintunOpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> *mut c_void;
type WintunCloseAdapterFn = unsafe extern "system" fn(adapter: *mut c_void);
type WintunDeleteDriverFn = unsafe extern "system" fn() -> i32;
type WintunGetAdapterLUIDFn = unsafe extern "system" fn(adapter: *mut c_void, luid: *mut u64);
type WintunGetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;
type WintunSetLoggerFn =
    unsafe extern "system" fn(logger: Option<unsafe extern "system" fn(u32, u64, *const u16)>);
type WintunStartSessionFn =
    unsafe extern "system" fn(adapter: *mut c_void, capacity: u32) -> *mut c_void;
type WintunEndSessionFn = unsafe extern "system" fn(session: *mut c_void);
type WintunGetReadWaitEventFn = unsafe extern "system" fn(session: *mut c_void) -> *mut c_void;
type WintunReceivePacketFn =
    unsafe extern "system" fn(session: *mut c_void, packet_size: *mut u32) -> *mut u8;
type WintunReleaseReceivePacketFn =
    unsafe extern "system" fn(session: *mut c_void, packet: *const u8);
type WintunAllocateSendPacketFn =
    unsafe extern "system" fn(session: *mut c_void, packet_size: u32) -> *mut u8;
type WintunSendPacketFn = unsafe extern "system" fn(session: *mut c_void, packet: *const u8);

static LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn test_logger(level: u32, _timestamp: u64, message: *const u16) {
    LOG_COUNT.fetch_add(1, Ordering::SeqCst);
    if !message.is_null() {
        let len = (0..512)
            .position(|i| unsafe { *message.add(i) == 0 })
            .unwrap_or(512);
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(message, len) });
        println!("[Wintun Log Level {}] {}", level, s);
    }
}

#[test]
fn test_wintun_dll_exports_and_loading() {
    let mut candidates = vec![
        std::path::PathBuf::from("target\\release\\wintun.dll"),
        std::path::PathBuf::from("..\\target\\release\\wintun.dll"),
    ];
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(std::path::PathBuf::from(td).join("release\\wintun.dll"));
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        candidates.push(
            std::path::PathBuf::from(home).join(".cargo\\shared-target\\release\\wintun.dll"),
        );
    }

    let dll_file = candidates.into_iter().find(|p| p.exists());
    let Some(dll_file) = dll_file else {
        println!("wintun.dll not found, skipping dynamic loading test");
        return;
    };

    let dll_path: Vec<u16> = dll_file
        .to_str()
        .unwrap()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let module: HMODULE = unsafe { LoadLibraryW(dll_path.as_ptr()) };
    assert!(!module.is_null(), "Failed to load {:?}", dll_file);

    macro_rules! get_sym {
        ($name:expr, $ty:ty) => {{
            let sym = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
            assert!(sym.is_some(), "Export {} not found in wintun.dll", $name);
            unsafe { std::mem::transmute::<_, $ty>(sym.unwrap()) }
        }};
    }

    let wintun_create_adapter: WintunCreateAdapterFn =
        get_sym!("WintunCreateAdapter", WintunCreateAdapterFn);
    let wintun_open_adapter: WintunOpenAdapterFn =
        get_sym!("WintunOpenAdapter", WintunOpenAdapterFn);
    let wintun_close_adapter: WintunCloseAdapterFn =
        get_sym!("WintunCloseAdapter", WintunCloseAdapterFn);
    let _wintun_delete_driver: WintunDeleteDriverFn =
        get_sym!("WintunDeleteDriver", WintunDeleteDriverFn);
    let wintun_get_adapter_luid: WintunGetAdapterLUIDFn =
        get_sym!("WintunGetAdapterLUID", WintunGetAdapterLUIDFn);
    let wintun_get_running_driver_version: WintunGetRunningDriverVersionFn = get_sym!(
        "WintunGetRunningDriverVersion",
        WintunGetRunningDriverVersionFn
    );
    let wintun_set_logger: WintunSetLoggerFn = get_sym!("WintunSetLogger", WintunSetLoggerFn);
    let wintun_start_session: WintunStartSessionFn =
        get_sym!("WintunStartSession", WintunStartSessionFn);
    let wintun_end_session: WintunEndSessionFn = get_sym!("WintunEndSession", WintunEndSessionFn);
    let wintun_get_read_wait_event: WintunGetReadWaitEventFn =
        get_sym!("WintunGetReadWaitEvent", WintunGetReadWaitEventFn);
    let wintun_receive_packet: WintunReceivePacketFn =
        get_sym!("WintunReceivePacket", WintunReceivePacketFn);
    let wintun_release_receive_packet: WintunReleaseReceivePacketFn =
        get_sym!("WintunReleaseReceivePacket", WintunReleaseReceivePacketFn);
    let wintun_allocate_send_packet: WintunAllocateSendPacketFn =
        get_sym!("WintunAllocateSendPacket", WintunAllocateSendPacketFn);
    let wintun_send_packet: WintunSendPacketFn = get_sym!("WintunSendPacket", WintunSendPacketFn);

    // 1. Test setting logger callback
    unsafe {
        wintun_set_logger(Some(test_logger));
    }

    // 2. Test querying running driver version
    let version = unsafe { wintun_get_running_driver_version() };
    println!("Running driver version: 0x{:08X}", version);

    // 3. Test null-safety of API boundary
    unsafe {
        wintun_close_adapter(std::ptr::null_mut());
        assert!(wintun_open_adapter(std::ptr::null()).is_null());
        wintun_end_session(std::ptr::null_mut());
        wintun_get_adapter_luid(std::ptr::null_mut(), std::ptr::null_mut());
        assert!(wintun_get_read_wait_event(std::ptr::null_mut()).is_null());
        assert!(wintun_start_session(std::ptr::null_mut(), 0x20000).is_null());
        assert!(wintun_receive_packet(std::ptr::null_mut(), std::ptr::null_mut()).is_null());
        wintun_release_receive_packet(std::ptr::null_mut(), std::ptr::null());
        assert!(wintun_allocate_send_packet(std::ptr::null_mut(), 100).is_null());
        wintun_send_packet(std::ptr::null_mut(), std::ptr::null());
    }

    // 4. Test Adapter Creation / Open / Session lifecycle
    let adapter_name: Vec<u16> = "TestAdapter\0".encode_utf16().collect();
    let tunnel_type: Vec<u16> = "Wintun\0".encode_utf16().collect();

    let adapter = unsafe {
        wintun_create_adapter(
            adapter_name.as_ptr(),
            tunnel_type.as_ptr(),
            std::ptr::null(),
        )
    };

    if !adapter.is_null() {
        println!("Successfully created adapter! Running full session test...");

        let mut luid: u64 = 0;
        unsafe {
            wintun_get_adapter_luid(adapter, &mut luid);
        }
        println!("Adapter LUID: 0x{:016X}", luid);
        assert_ne!(luid, 0);

        // Start session
        let session = unsafe { wintun_start_session(adapter, 0x40000) }; // 256KiB ring
        assert!(!session.is_null(), "Failed to start session");

        let wait_event = unsafe { wintun_get_read_wait_event(session) };
        assert!(!wait_event.is_null(), "Wait event handle is null");

        // Test allocating and sending a mock IP packet (20-byte IPv4 header)
        let send_ptr = unsafe { wintun_allocate_send_packet(session, 20) };
        assert!(!send_ptr.is_null(), "Failed to allocate send packet");

        unsafe {
            // Write mock IPv4 packet (version 4, IHL 5, total length 20)
            *send_ptr = 0x45;
            wintun_send_packet(session, send_ptr);
        }

        // Test receiving packet (should be empty initially)
        let mut rx_size: u32 = 0;
        let rx_ptr = unsafe { wintun_receive_packet(session, &mut rx_size) };
        if !rx_ptr.is_null() {
            unsafe {
                wintun_release_receive_packet(session, rx_ptr);
            }
        }

        // End session
        unsafe {
            wintun_end_session(session);
        }

        // Test WintunOpenAdapter on existing adapter
        let opened_adapter = unsafe { wintun_open_adapter(adapter_name.as_ptr()) };
        if !opened_adapter.is_null() {
            println!("Successfully opened existing adapter!");
            unsafe { wintun_close_adapter(opened_adapter) };
        }
        // Close the created adapter handle to remove the adapter
        unsafe { wintun_close_adapter(adapter) };

        println!("Adapter lifecycle test completed successfully.");
    } else {
        let err = unsafe { GetLastError() };
        println!(
            "WintunCreateAdapter returned NULL (Last Error: 0x{:08X})",
            err
        );
        if err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_ACCESS_DENIED {
            println!(
                "Note: Creating network adapter requires Administrator privileges on Windows. API boundary correctly verified."
            );
        }
    }

    unsafe {
        wintun_set_logger(None);
        FreeLibrary(module);
    }
}
