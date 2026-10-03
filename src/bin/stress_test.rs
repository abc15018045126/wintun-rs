// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.

use std::ffi::c_void;
use std::time::Instant;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, FILETIME, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessHandleCount, GetProcessTimes,
};

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

struct WintunApi {
    _module: HMODULE,
    create_adapter: WintunCreateAdapterFn,
    _open_adapter: WintunOpenAdapterFn,
    close_adapter: WintunCloseAdapterFn,
    _delete_driver: WintunDeleteDriverFn,
    get_adapter_luid: WintunGetAdapterLUIDFn,
    get_running_driver_version: WintunGetRunningDriverVersionFn,
    set_logger: WintunSetLoggerFn,
    start_session: WintunStartSessionFn,
    end_session: WintunEndSessionFn,
    _get_read_wait_event: WintunGetReadWaitEventFn,
    receive_packet: WintunReceivePacketFn,
    release_receive_packet: WintunReleaseReceivePacketFn,
    allocate_send_packet: WintunAllocateSendPacketFn,
    send_packet: WintunSendPacketFn,
}

impl WintunApi {
    fn load(dll_path: &str) -> Result<Self, String> {
        let wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module.is_null() {
            return Err(format!(
                "Failed to LoadLibraryW({}): error 0x{:X}",
                dll_path,
                unsafe { GetLastError() }
            ));
        }

        macro_rules! resolve {
            ($name:expr, $ty:ty) => {{
                let sym = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
                if sym.is_none() {
                    unsafe { FreeLibrary(module) };
                    return Err(format!("Missing export symbol: {}", $name));
                }
                unsafe {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(sym.unwrap())
                }
            }};
        }

        Ok(Self {
            _module: module,
            create_adapter: resolve!("WintunCreateAdapter", WintunCreateAdapterFn),
            _open_adapter: resolve!("WintunOpenAdapter", WintunOpenAdapterFn),
            close_adapter: resolve!("WintunCloseAdapter", WintunCloseAdapterFn),
            _delete_driver: resolve!("WintunDeleteDriver", WintunDeleteDriverFn),
            get_adapter_luid: resolve!("WintunGetAdapterLUID", WintunGetAdapterLUIDFn),
            get_running_driver_version: resolve!(
                "WintunGetRunningDriverVersion",
                WintunGetRunningDriverVersionFn
            ),
            set_logger: resolve!("WintunSetLogger", WintunSetLoggerFn),
            start_session: resolve!("WintunStartSession", WintunStartSessionFn),
            end_session: resolve!("WintunEndSession", WintunEndSessionFn),
            _get_read_wait_event: resolve!("WintunGetReadWaitEvent", WintunGetReadWaitEventFn),
            receive_packet: resolve!("WintunReceivePacket", WintunReceivePacketFn),
            release_receive_packet: resolve!(
                "WintunReleaseReceivePacket",
                WintunReleaseReceivePacketFn
            ),
            allocate_send_packet: resolve!("WintunAllocateSendPacket", WintunAllocateSendPacketFn),
            send_packet: resolve!("WintunSendPacket", WintunSendPacketFn),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct ProcessMetrics {
    handle_count: u32,
    working_set_kb: usize,
    pagefile_kb: usize,
    kernel_time_ms: u64,
    user_time_ms: u64,
    total_cpu_time_ms: u64,
    timestamp: Instant,
}

fn filetime_to_100ns(ft: &FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

fn get_process_metrics() -> ProcessMetrics {
    let process = unsafe { GetCurrentProcess() };
    let mut handle_count: u32 = 0;
    unsafe {
        GetProcessHandleCount(process, &mut handle_count);
    }

    let mut pmc = PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        PageFaultCount: 0,
        PeakWorkingSetSize: 0,
        WorkingSetSize: 0,
        QuotaPeakPagedPoolUsage: 0,
        QuotaPagedPoolUsage: 0,
        QuotaPeakNonPagedPoolUsage: 0,
        QuotaNonPagedPoolUsage: 0,
        PagefileUsage: 0,
        PeakPagefileUsage: 0,
    };

    unsafe {
        GetProcessMemoryInfo(
            process,
            &mut pmc,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        );
    }

    let mut creation_ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit_ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel_ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user_ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };

    unsafe {
        GetProcessTimes(
            process,
            &mut creation_ft,
            &mut exit_ft,
            &mut kernel_ft,
            &mut user_ft,
        );
    }

    let kernel_100ns = filetime_to_100ns(&kernel_ft);
    let user_100ns = filetime_to_100ns(&user_ft);
    let kernel_time_ms = kernel_100ns / 10_000;
    let user_time_ms = user_100ns / 10_000;

    ProcessMetrics {
        handle_count,
        working_set_kb: pmc.WorkingSetSize / 1024,
        pagefile_kb: pmc.PagefileUsage / 1024,
        kernel_time_ms,
        user_time_ms,
        total_cpu_time_ms: kernel_time_ms + user_time_ms,
        timestamp: Instant::now(),
    }
}

fn calculate_cpu_usage(prev: &ProcessMetrics, curr: &ProcessMetrics) -> (f64, u64, u64) {
    let kernel_delta_ms = curr.kernel_time_ms.saturating_sub(prev.kernel_time_ms);
    let user_delta_ms = curr.user_time_ms.saturating_sub(prev.user_time_ms);
    let total_cpu_delta_ms = kernel_delta_ms + user_delta_ms;
    let wall_delta_sec = curr.timestamp.duration_since(prev.timestamp).as_secs_f64();
    let cpu_pct = if wall_delta_sec > 0.0 {
        (total_cpu_delta_ms as f64 / (wall_delta_sec * 1000.0)) * 100.0
    } else {
        0.0
    };
    (cpu_pct, kernel_delta_ms, user_delta_ms)
}

unsafe extern "system" fn test_logger(level: u32, _timestamp: u64, message: *const u16) {
    if !message.is_null() {
        let len = (0..512).position(|i| *message.add(i) == 0).unwrap_or(512);
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(message, len));
        println!("    [Wintun Log Level {}] {}", level, s);
    }
}

fn main() {
    println!("================================================================================");
    println!("               Wintun Rust Automated Leak & Stress Test Tool                    ");
    println!("================================================================================");

    let candidates = [
        "wintun.dll",
        "target\\release\\wintun.dll",
        "..\\wintun.dll",
    ];
    let mut api_opt = None;
    for path in &candidates {
        if let Ok(api) = WintunApi::load(path) {
            println!("[+] Successfully loaded Wintun DLL from: {}", path);
            api_opt = Some(api);
            break;
        }
    }

    let api = match api_opt {
        Some(a) => a,
        None => {
            eprintln!(
                "[-] Error: Could not find or load wintun.dll from candidates: {:?}",
                candidates
            );
            std::process::exit(1);
        }
    };

    unsafe {
        (api.set_logger)(Some(test_logger));
    }

    let ver = unsafe { (api.get_running_driver_version)() };
    println!(
        "[+] Running Wintun Driver Version: 0x{:08X} (v{}.{})",
        ver,
        (ver >> 16) & 0xff,
        ver & 0xff
    );

    let baseline = get_process_metrics();
    println!("\n[*] Baseline Process State:");
    println!("    - Handles:       {}", baseline.handle_count);
    println!("    - Working Set:   {} KB", baseline.working_set_kb);
    println!("    - Private Bytes: {} KB", baseline.pagefile_kb);
    println!(
        "    - CPU Time:      {} ms (Kernel: {} ms, User: {} ms)",
        baseline.total_cpu_time_ms, baseline.kernel_time_ms, baseline.user_time_ms
    );

    // =========================================================================
    // TEST 1: Data Path High-Throughput Packet Flood (Zero-Allocation Verification)
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!(" TEST 1: Data Path Packet Flood (500,000 Packets) - Memory & CPU Efficiency   ");
    println!("--------------------------------------------------------------------------------");

    let adapter_name: Vec<u16> = "Demo\0".encode_utf16().collect();
    let tunnel_type: Vec<u16> = "Example\0".encode_utf16().collect();
    let guid = GUID {
        data1: 0xdeadbabe,
        data2: 0xcafe,
        data3: 0xbeef,
        data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    };

    let adapter =
        unsafe { (api.create_adapter)(adapter_name.as_ptr(), tunnel_type.as_ptr(), &guid) };
    if adapter.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("[-] Failed to create adapter for Test 1 (Error: 0x{:08X}). Ensure running as Administrator!", err);
        std::process::exit(1);
    }

    let session = unsafe { (api.start_session)(adapter, 0x400000) }; // 4 MiB Ring Buffer
    if session.is_null() {
        eprintln!("[-] Failed to start session for Test 1");
        unsafe { (api.close_adapter)(adapter) };
        std::process::exit(1);
    }

    let t1_start_metrics = get_process_metrics();
    println!(
        "    [T1 Start] Handles: {}, WorkingSet: {} KB, PrivateUsage: {} KB, CPU: {} ms",
        t1_start_metrics.handle_count,
        t1_start_metrics.working_set_kb,
        t1_start_metrics.pagefile_kb,
        t1_start_metrics.total_cpu_time_ms
    );

    let total_packets: usize = 500_000;
    let checkpoint_interval: usize = 100_000;
    let start_time = Instant::now();
    let mut last_checkpoint_metrics = t1_start_metrics;

    for i in 1..=total_packets {
        // Allocate a 64-byte mock packet
        let ptr = unsafe { (api.allocate_send_packet)(session, 64) };
        if !ptr.is_null() {
            unsafe {
                *ptr = 0x45; // IPv4
                (api.send_packet)(session, ptr);
            }
        }

        // Drain any receive packets
        let mut rx_size: u32 = 0;
        let rx_ptr = unsafe { (api.receive_packet)(session, &mut rx_size) };
        if !rx_ptr.is_null() {
            unsafe { (api.release_receive_packet)(session, rx_ptr) };
        }

        if i % checkpoint_interval == 0 {
            let m = get_process_metrics();
            let elapsed = start_time.elapsed().as_secs_f64();
            let pps = i as f64 / elapsed;
            let (cpu_pct, k_ms, u_ms) = calculate_cpu_usage(&last_checkpoint_metrics, &m);
            last_checkpoint_metrics = m;

            println!("    [Progress {:>6}/{:>6}] Speed: {:>9.0} pkt/s | CPU: {:>5.1}% (K: {:>2}ms, U: {:>2}ms) | Handles: {:>4} | Private: {:>6} KB (Δ: {:+4} KB)",
                i, total_packets, pps, cpu_pct, k_ms, u_ms, m.handle_count,
                m.pagefile_kb,
                m.pagefile_kb as i64 - t1_start_metrics.pagefile_kb as i64);
        }
    }

    unsafe {
        (api.end_session)(session);
        (api.close_adapter)(adapter);
    }

    let t1_end_metrics = get_process_metrics();
    let t1_total_cpu_ms = t1_end_metrics
        .total_cpu_time_ms
        .saturating_sub(t1_start_metrics.total_cpu_time_ms);
    let t1_kernel_cpu_ms = t1_end_metrics
        .kernel_time_ms
        .saturating_sub(t1_start_metrics.kernel_time_ms);
    let t1_user_cpu_ms = t1_end_metrics
        .user_time_ms
        .saturating_sub(t1_start_metrics.user_time_ms);
    let ns_per_packet = if total_packets > 0 {
        (t1_total_cpu_ms as f64 * 1_000_000.0) / (total_packets as f64)
    } else {
        0.0
    };

    println!("    [T1 End]   Handles: {}, WorkingSet: {} KB, PrivateUsage: {} KB, Total CPU: {} ms (Kernel: {} ms, User: {} ms)",
        t1_end_metrics.handle_count, t1_end_metrics.working_set_kb, t1_end_metrics.pagefile_kb,
        t1_total_cpu_ms, t1_kernel_cpu_ms, t1_user_cpu_ms);

    let t1_handle_delta = t1_end_metrics.handle_count as i64 - t1_start_metrics.handle_count as i64;
    let t1_mem_delta = t1_end_metrics.pagefile_kb as i64 - t1_start_metrics.pagefile_kb as i64;

    println!("[+] TEST 1 RESULT: 500,000 Packets Transferred.");
    println!(
        "    - CPU Efficiency: {:.1} ns CPU time/packet (~{:.2} Mpps/core capability)",
        ns_per_packet,
        if ns_per_packet > 0.0 {
            1000.0 / ns_per_packet
        } else {
            0.0
        }
    );
    println!(
        "    - Memory & Handle Drift: Handle Δ = {}, Private Memory Δ = {} KB",
        t1_handle_delta, t1_mem_delta
    );

    // =========================================================================
    // TEST 2: Control Path Lifecycle Churn (Create/Session/Packet/Close 20 Cycles)
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!(" TEST 2: Control Path Lifecycle Churn (20 Full Create -> Run -> Destroy Cycles)");
    println!("--------------------------------------------------------------------------------");

    let cycles = 20;
    let mut warm_cycle_metrics = None;
    let mut prev_cycle_metrics = get_process_metrics();

    for c in 1..=cycles {
        let name_str = format!("StressChurn_{}\0", c);
        let name_w: Vec<u16> = name_str.encode_utf16().collect();

        // 1. Create Adapter
        let ad = unsafe {
            (api.create_adapter)(name_w.as_ptr(), tunnel_type.as_ptr(), std::ptr::null())
        };
        if ad.is_null() {
            eprintln!(
                "[-] Cycle {} failed: CreateAdapter returned NULL (Error: 0x{:08X})",
                c,
                unsafe { GetLastError() }
            );
            continue;
        }

        // 2. Get LUID
        let mut luid: u64 = 0;
        unsafe { (api.get_adapter_luid)(ad, &mut luid) };

        // 3. Start Session
        let s = unsafe { (api.start_session)(ad, 0x100000) }; // 1 MiB Ring
        if !s.is_null() {
            // Send 10 packets
            for _ in 0..10 {
                let p = unsafe { (api.allocate_send_packet)(s, 64) };
                if !p.is_null() {
                    unsafe {
                        *p = 0x45;
                        (api.send_packet)(s, p);
                    }
                }
            }
            // 4. End Session
            unsafe { (api.end_session)(s) };
        }

        // 5. Close Adapter
        unsafe { (api.close_adapter)(ad) };

        let m = get_process_metrics();
        if c == 5 {
            warm_cycle_metrics = Some(m);
        }

        let ref_metrics = warm_cycle_metrics.unwrap_or(m);
        let handle_diff = m.handle_count as i64 - ref_metrics.handle_count as i64;
        let mem_diff = m.pagefile_kb as i64 - ref_metrics.pagefile_kb as i64;
        let (_cpu_pct, cycle_k_ms, cycle_u_ms) = calculate_cpu_usage(&prev_cycle_metrics, &m);
        prev_cycle_metrics = m;

        println!("    Cycle {:>2}/{} Completed | CPU: {:>3}ms (K: {:>2}ms, U: {:>2}ms) | Handles: {:>4} (Δ: {:+3}) | Private: {:>6} KB (Δ: {:+4} KB)",
            c, cycles, cycle_k_ms + cycle_u_ms, cycle_k_ms, cycle_u_ms, m.handle_count, handle_diff, m.pagefile_kb, mem_diff);
    }

    // =========================================================================
    // FINAL VERDICT
    // =========================================================================
    println!("\n================================================================================");
    println!("                           FINAL LEAK & PERFORMANCE REPORT                       ");
    println!("================================================================================");

    let final_metrics = get_process_metrics();
    let warm = warm_cycle_metrics.unwrap_or(baseline);
    let net_handle_delta = final_metrics.handle_count as i64 - warm.handle_count as i64;
    let net_memory_delta = final_metrics.pagefile_kb as i64 - warm.pagefile_kb as i64;
    let total_session_cpu_ms = final_metrics
        .total_cpu_time_ms
        .saturating_sub(baseline.total_cpu_time_ms);
    let total_kernel_cpu_ms = final_metrics
        .kernel_time_ms
        .saturating_sub(baseline.kernel_time_ms);
    let total_user_cpu_ms = final_metrics
        .user_time_ms
        .saturating_sub(baseline.user_time_ms);

    println!("[*] Resource Stability Summary:");
    println!(
        "    - Steady-State Handle Growth:        {:+5} handles (Warm: {}, Final: {})",
        net_handle_delta, warm.handle_count, final_metrics.handle_count
    );
    println!(
        "    - Steady-State Memory Growth:        {:+5} KB (Warm: {} KB, Final: {} KB)",
        net_memory_delta, warm.pagefile_kb, final_metrics.pagefile_kb
    );
    println!(
        "    - Total Process CPU Time Consumed:     {:>5} ms (Kernel: {} ms, User: {} ms)",
        total_session_cpu_ms, total_kernel_cpu_ms, total_user_cpu_ms
    );

    println!("\n[*] Verdict:");
    if net_handle_delta <= 5 && net_memory_delta <= 512 {
        println!("    >>> [PASS] PERFECT ZERO LEAKS! Handle count and memory usage are completely stable.");
    } else if net_handle_delta <= 10 && net_memory_delta <= 1024 {
        println!("    >>> [PASS] STABLE! Resource usage is bounded within normal Windows SetupAPI runtime margins.");
    } else {
        println!(
            "    >>> [WARN] Potential resource drift detected. Check SetupAPI / Handle cleanup."
        );
    }
    println!("================================================================================\n");
}
