# wintun-rs

[![Crates.io](https://img.shields.io/crates/v/wintun-rs.svg)](https://crates.io/crates/wintun-rs)
[![Documentation](https://docs.rs/wintun-rs/badge.svg)](https://docs.rs/wintun-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**wintun-rs** is a pure Rust reimplementation of the [WireGuard Wintun](https://github.com/WireGuard/wintun) userspace library for Windows TUN network adapters.

Unlike simple FFI wrappers, **wintun-rs** provides a 100% native Rust userspace stack, embedding the signed kernel driver binaries directly and exposing safe, idiomatic Rust abstractions without requiring an external `wintun.dll` on disk.

---

## Key Highlights

- **100% Safe Native Rust API**: High-level abstractions (`Adapter`, `Session`, `Packet`, `SendPacket`) that eliminate `unsafe` code in downstream applications.
- **Zero DLL Dependency**: The driver files (`wintun.sys`, `wintun.inf`, `wintun.cat`) are embedded into the library binary via `include_bytes!`. No external `wintun.dll` is required on the user's filesystem.
- **Automatic Resource Cleanup (RAII)**: All Windows OS handles (`HDEVINFO`, registry keys, event objects, ring buffer allocations, and adapters) are guarded with automatic `Drop` implementations to prevent leaks.
- **Legacy Device Cleanup**: Automatically cleans up orphaned or stale Wintun adapters from previous unexpected process terminations.
- **Dual-Mode Output**:
  - Use directly as a standard Rust dependency (`rlib`) in your application.
  - Or compile to a drop-in C-compatible `wintun.dll` (`cdylib`) matching the official WireGuard exports.

---

## Comparison: `wintun-rs` vs. Existing `wintun` Crate (0.5.1)

| Feature | crates.io `wintun` (0.5.1) | **wintun-rs** (This Crate) |
| :--- | :--- | :--- |
| **Architecture** | Dynamic `LoadLibrary` wrapper around `wintun.dll` | **Full native Rust reimplementation** of Wintun userspace logic |
| **External Files Required** | **Requires** `wintun.dll` on disk alongside the executable | **None**; driver binaries are embedded directly into your binary |
| **Driver Staging** | Must be installed or downloaded separately by user | **Automatic**; extracts and installs driver via Windows SetupAPI |
| **Safety** | Requires `unsafe { wintun::load(...) }` dynamic calls | **100% Safe Rust**; type-safe API with compile-time checks |
| **Build Target** | Consumer only (cannot produce a DLL) | **Dual-mode**: Can be linked as a Rust library or built as `wintun.dll` |

---

## Installation

Add **wintun-rs** to your `Cargo.toml`:

```toml
[dependencies]
wintun = { package = "wintun-rs", version = "0.0.4" }
```

Or via `cargo`:

```bash
cargo add wintun-rs
```

*(Note: Although the package is published as `wintun-rs`, the library crate name is `wintun`, so you can write `use wintun::Adapter;` naturally.)*

---

## Quick Example

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use wintun::Adapter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create or open a Wintun adapter (Administrator privilege required)
    let adapter = Adapter::create("DemoAdapter", "ExampleTunnel", None)
        .or_else(|_| Adapter::open("DemoAdapter"))?;

    println!("Adapter created. LUID: 0x{:016X}", adapter.get_luid().value);

    // 2. Start a TUN session with 4MB ring buffer capacity
    let session = Arc::new(adapter.start_session(0x400000)?);

    // 3. Receive incoming packets in a worker thread
    let recv_session = session.clone();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let recv_thread = thread::spawn(move || {
        while r.load(Ordering::Relaxed) {
            let mut had_packet = false;
            // Drain all available packets from ring buffer
            while let Ok(Some(packet)) = recv_session.receive_packet() {
                had_packet = true;
                println!("Received IP packet: {} bytes", packet.len());
                // `packet` automatically frees its ring slot when dropped!
            }

            // Wait for Wintun event signal if ring is currently empty
            if !had_packet {
                recv_session.wait_for_data(50);
            }
        }
    });

    // 4. Send an IP packet
    let mut send_packet = session.allocate_send_packet(28)?;
    // Fill packet data (IPv4 header + payload)...
    send_packet[0] = 0x45; // IPv4
    // Dispatch packet directly to ring buffer:
    session.send_packet(send_packet);

    // 5. Shutdown and cleanup
    thread::sleep(Duration::from_secs(3));
    running.store(false, Ordering::Relaxed);
    recv_thread.join().unwrap();

    // Adapter and Session automatically release all handles when dropped!
    Ok(())
}
```

A complete runnable sample is available in [`example/example.rs`](example/example.rs). You can run it with:

```bash
cargo run --example example
```

---

## Building a C-Compatible `wintun.dll`

If you need a drop-in replacement for `wintun.dll` to use with C, C++, Go, or Python:

```bash
cargo build --release
```

The resulting `target/release/wintun.dll` exports all official Wintun C functions:
- `WintunCreateAdapter`
- `WintunOpenAdapter`
- `WintunCloseAdapter`
- `WintunDeleteDriver`
- `WintunGetAdapterLUID`
- `WintunGetRunningDriverVersion`
- `WintunSetLogger`
- `WintunStartSession`
- `WintunEndSession`
- `WintunGetReadWaitEvent`
- `WintunReceivePacket`
- `WintunReleaseReceivePacket`
- `WintunAllocateSendPacket`
- `WintunSendPacket`

---

## Acknowledgements & Credits

This project is a Rust reimplementation of the official **Wintun** project developed by WireGuard:
- **Official Repository**: [https://git.zx2c4.com/wintun](https://git.zx2c4.com/wintun)
- **GitHub Mirror**: [WireGuard/wintun](https://github.com/WireGuard/wintun)
- **Original Author**: [Jason A. Donenfeld](https://www.zx2c4.com/) / WireGuard LLC

We extend our deep gratitude to Jason A. Donenfeld and the WireGuard team for creating the high-performance Wintun architecture and Windows TUN driver.

---

## License

This project is licensed under the [MIT License](LICENSE).
