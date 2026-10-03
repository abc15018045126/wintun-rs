//! # Wintun-rs Safe Rust Example
//!
//! Demonstrates how to create a Wintun TUN adapter, start a session,
//! receive incoming packets, and send an ICMP packet using safe idiomatic Rust.
//!
//! Equivalent to the C implementation in `example.c`, but:
//! - 100% Safe Rust without manual pointer manipulation or dynamic DLL loading
//! - Automatic resource cleanup (Adapter, Session, Packets) via RAII Drop guards
//! - No external wintun.dll required on disk (embedded driver binaries)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use wintun::Adapter;

/// Computes the standard internet checksum (RFC 1071).
fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Constructs a simple IPv4 ICMP Echo Request packet (28 bytes).
fn make_icmp_echo_request(packet: &mut [u8]) {
    packet.fill(0);
    // IPv4 Header (20 bytes)
    packet[0] = 0x45; // Version 4, IHL 5
    packet[1] = 0x00; // DSCP / ECN
    packet[2..4].copy_from_slice(&28u16.to_be_bytes()); // Total length 28
    packet[4..6].copy_from_slice(&1u16.to_be_bytes());  // Identification
    packet[6..8].copy_from_slice(&0u16.to_be_bytes());  // Flags / Fragment offset
    packet[8] = 64;   // TTL
    packet[9] = 1;    // Protocol: ICMP
    packet[12..16].copy_from_slice(&[10, 6, 7, 7]);     // Source IP: 10.6.7.7
    packet[16..20].copy_from_slice(&[10, 6, 7, 8]);     // Dest IP: 10.6.7.8

    let ip_cksum = ip_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ICMP Header (8 bytes)
    packet[20] = 8; // Type: Echo Request
    packet[21] = 0; // Code: 0
    packet[24..26].copy_from_slice(&0x1234u16.to_be_bytes()); // Identifier
    packet[26..28].copy_from_slice(&1u16.to_be_bytes());      // Sequence number

    let icmp_cksum = ip_checksum(&packet[20..28]);
    packet[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());
}

/// Parses and prints basic packet header information.
fn print_packet(packet: &[u8]) {
    if packet.len() < 20 {
        println!("[Recv] Packet too short for IP header ({} bytes)", packet.len());
        return;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            let proto = packet[9];
            let src = format!("{}.{}.{}.{}", packet[12], packet[13], packet[14], packet[15]);
            let dst = format!("{}.{}.{}.{}", packet[16], packet[17], packet[18], packet[19]);
            println!(
                "[Recv IPv4] proto=0x{:02x}, len={}, src={}, dst={}",
                proto,
                packet.len(),
                src,
                dst
            );
        }
        6 => {
            if packet.len() < 40 {
                return;
            }
            let proto = packet[6];
            println!("[Recv IPv6] next_header=0x{:02x}, len={}", proto, packet.len());
        }
        _ => {
            println!("[Recv] Unknown IP version {}: {} bytes", version, packet.len());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Wintun-rs Safe Rust Example ===");
    println!("Running driver version: 0x{:08X}", Adapter::running_driver_version());

    // 1. Create or open the Wintun adapter (Name: "Demo", Type: "Example")
    println!("[1/4] Creating Wintun adapter 'Demo'...");
    let adapter = Adapter::create("Demo", "Example", None)
        .or_else(|_| Adapter::open("Demo"))
        .map_err(|e| format!("Failed to create/open adapter: {}", e))?;

    let luid = adapter.get_luid();
    println!("      Adapter created successfully! LUID Value: 0x{:016X}", luid.value);

    // 2. Start a session with 4MB ring buffer capacity
    println!("[2/4] Starting TUN session (capacity: 4MB)...");
    let session = Arc::new(
        adapter
            .start_session(0x400000)
            .map_err(|e| format!("Failed to start session: {}", e))?,
    );
    println!("      Session started successfully. Ring buffers active.");

    // 3. Setup running flag for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));

    // 4. Spawn receive thread
    println!("[3/4] Spawning packet receive worker thread...");
    let recv_session = session.clone();
    let recv_running = running.clone();
    let recv_thread = thread::spawn(move || {
        while recv_running.load(Ordering::Relaxed) {
            let mut had_packet = false;
            // Drain all available packets from ring buffer
            while let Ok(Some(packet)) = recv_session.receive_packet() {
                had_packet = true;
                // Packet implements Deref<Target = [u8]>
                print_packet(&packet);
                // `packet` slot in the ring buffer is automatically released on drop
            }

            // If no packets were available, wait up to 50ms for Wintun event signal
            if !had_packet {
                recv_session.wait_for_data(50);
            }
        }
        println!("      Receive worker thread exited cleanly.");
    });

    // 5. Send periodic ICMP packets in main loop
    println!("[4/4] Sending sample ICMP packets every 2 seconds (Ctrl+C to stop)...");
    for i in 1..=5 {
        if !running.load(Ordering::Relaxed) {
            break;
        }

        // Allocate a 28-byte send packet buffer in the ring
        match session.allocate_send_packet(28) {
            Ok(mut send_pkt) => {
                // SendPacket implements DerefMut<Target = [u8]>
                make_icmp_echo_request(&mut send_pkt);
                // Dispatch packet directly to Wintun ring buffer
                session.send_packet(send_pkt);
                println!("      [{}] Sent ICMP Echo Request (28 bytes)", i);
            }
            Err(err) => {
                eprintln!("Failed to allocate send packet: {:?}", err);
            }
        }

        thread::sleep(Duration::from_secs(2));
    }

    // Stop and cleanup
    println!("\nShutting down example...");
    running.store(false, Ordering::Relaxed);
    let _ = recv_thread.join();

    println!("All done. Adapter and Session will be closed automatically via RAII Drop.");
    Ok(())
}
