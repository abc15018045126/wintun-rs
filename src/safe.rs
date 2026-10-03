use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Once;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, HANDLE};

use crate::adapter::{
    wintun_close_adapter, wintun_create_adapter, wintun_get_adapter_luid, wintun_open_adapter,
};
use crate::driver::{wintun_delete_driver, wintun_get_running_driver_version};
use crate::session::{
    wintun_allocate_send_packet, wintun_end_session, wintun_get_read_wait_event,
    wintun_receive_packet, wintun_release_receive_packet, wintun_send_packet,
    wintun_start_session,
};
use crate::types::{
    get_last_error, to_wide, NetLuid, TunSession, WintunAdapter, WINTUN_MAX_RING_CAPACITY,
    WINTUN_MIN_RING_CAPACITY,
};

static INIT: Once = Once::new();

/// Ensures Wintun security objects and driver state are initialized.
///
/// When using Wintun as a Rust static library (`rlib`), Windows DLL loader does not call `DllMain`.
/// This function ensures required initialization runs once.
pub fn ensure_initialized() {
    INIT.call_once(|| {
        crate::namespace::init_security_objects();
        crate::adapter::adapter_cleanup_legacy_devices();
    });
}

/// Safe RAII wrapper around a Wintun adapter.
pub struct Adapter {
    raw: *mut WintunAdapter,
    name: String,
}

unsafe impl Send for Adapter {}
unsafe impl Sync for Adapter {}

impl Adapter {
    /// Creates a new Wintun adapter.
    ///
    /// Mirrors `WintunCreateAdapter`.
    pub fn create(name: &str, tunnel_type: &str, requested_guid: Option<u128>) -> io::Result<Self> {
        ensure_initialized();
        let name_w = to_wide(name);
        let type_w = to_wide(tunnel_type);
        let guid_struct = requested_guid.map(|g| {
            let b = g.to_be_bytes();
            GUID {
                data1: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                data2: u16::from_be_bytes([b[4], b[5]]),
                data3: u16::from_be_bytes([b[6], b[7]]),
                data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
            }
        });
        let guid_ptr = guid_struct.as_ref().map_or(std::ptr::null(), |g| g as *const _);

        let raw = wintun_create_adapter(name_w.as_ptr(), type_w.as_ptr(), guid_ptr);
        if raw.is_null() {
            Err(io::Error::from_raw_os_error(get_last_error() as i32))
        } else {
            Ok(Self {
                raw,
                name: name.to_string(),
            })
        }
    }

    /// Creates a new Wintun adapter with a reference to a Win32 `GUID`.
    pub fn create_with_guid(name: &str, tunnel_type: &str, requested_guid: Option<&GUID>) -> io::Result<Self> {
        ensure_initialized();
        let name_w = to_wide(name);
        let type_w = to_wide(tunnel_type);
        let guid_ptr = requested_guid.map_or(std::ptr::null(), |g| g as *const _);

        let raw = wintun_create_adapter(name_w.as_ptr(), type_w.as_ptr(), guid_ptr);
        if raw.is_null() {
            Err(io::Error::from_raw_os_error(get_last_error() as i32))
        } else {
            Ok(Self {
                raw,
                name: name.to_string(),
            })
        }
    }

    /// Opens an existing Wintun adapter by name.
    ///
    /// Mirrors `WintunOpenAdapter`.
    pub fn open(name: &str) -> io::Result<Self> {
        ensure_initialized();
        let name_w = to_wide(name);
        let raw = wintun_open_adapter(name_w.as_ptr());
        if raw.is_null() {
            Err(io::Error::from_raw_os_error(get_last_error() as i32))
        } else {
            Ok(Self {
                raw,
                name: name.to_string(),
            })
        }
    }

    /// Gets the adapter name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the adapter NET_LUID.
    ///
    /// Mirrors `WintunGetAdapterLUID`.
    pub fn get_luid(&self) -> NetLuid {
        let mut luid = NetLuid::default();
        wintun_get_adapter_luid(self.raw, &mut luid);
        luid
    }

    /// Starts a session on the adapter with the given ring buffer capacity (between 128 KiB and 64 MiB).
    ///
    /// Mirrors `WintunStartSession`.
    pub fn start_session(&self, capacity: u32) -> io::Result<Session> {
        let cap = capacity.clamp(WINTUN_MIN_RING_CAPACITY, WINTUN_MAX_RING_CAPACITY);
        let raw = wintun_start_session(self.raw, cap);
        if raw.is_null() {
            Err(io::Error::from_raw_os_error(get_last_error() as i32))
        } else {
            Ok(Session {
                raw,
                capacity: cap,
            })
        }
    }

    /// Returns the raw pointer to WintunAdapter.
    #[inline]
    pub fn raw(&self) -> *mut WintunAdapter {
        self.raw
    }

    /// Deletes the installed Wintun driver.
    ///
    /// Mirrors `WintunDeleteDriver`.
    pub fn delete_driver() -> io::Result<()> {
        if wintun_delete_driver() {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(get_last_error() as i32))
        }
    }

    /// Returns the running Wintun driver version.
    ///
    /// Mirrors `WintunGetRunningDriverVersion`.
    #[inline]
    pub fn running_driver_version() -> u32 {
        wintun_get_running_driver_version()
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            wintun_close_adapter(self.raw);
            self.raw = std::ptr::null_mut();
        }
    }
}

/// Safe RAII wrapper around an active Wintun session.
pub struct Session {
    raw: *mut TunSession,
    capacity: u32,
}

unsafe impl Send for Session {}
unsafe impl Sync for Session {}

impl Session {
    /// Returns the Win32 event signaled when new packets are available to receive.
    ///
    /// Mirrors `WintunGetReadWaitEvent`.
    #[inline]
    pub fn read_wait_event(&self) -> HANDLE {
        wintun_get_read_wait_event(self.raw)
    }

    /// Waits for new packets to arrive or for `timeout_ms` to expire.
    ///
    /// Returns `true` if signaled with new data, or `false` on timeout or error.
    #[inline]
    pub fn wait_for_data(&self, timeout_ms: u32) -> bool {
        let event = self.read_wait_event();
        unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(event, timeout_ms)
                == windows_sys::Win32::Foundation::WAIT_OBJECT_0
        }
    }

    /// Receives a packet from the ring buffer.
    ///
    /// Returns `Ok(Some(packet))` if a packet was received, or `Ok(None)` if the ring buffer is empty (`ERROR_NO_MORE_ITEMS`).
    /// The returned `Packet` automatically releases its slot in the ring buffer when dropped.
    ///
    /// Mirrors `WintunReceivePacket`.
    pub fn receive_packet(&self) -> io::Result<Option<Packet<'_>>> {
        let mut size = 0u32;
        let ptr = wintun_receive_packet(self.raw, &mut size);
        if ptr.is_null() {
            let err = get_last_error();
            if err == ERROR_NO_MORE_ITEMS {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(err as i32))
            }
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, size as usize) };
            Ok(Some(Packet {
                session: self.raw,
                ptr,
                bytes,
            }))
        }
    }

    /// Allocates buffer space for a packet to be sent through the TUN interface.
    ///
    /// Fill the returned `SendPacket` with IP packet data and call `session.send_packet(send_packet)`
    /// or `send_packet.send()`.
    ///
    /// Mirrors `WintunAllocateSendPacket`.
    pub fn allocate_send_packet(&self, size: u32) -> io::Result<SendPacket<'_>> {
        let ptr = wintun_allocate_send_packet(self.raw, size);
        if ptr.is_null() {
            let err = get_last_error();
            Err(io::Error::from_raw_os_error(err as i32))
        } else {
            let buf = unsafe { std::slice::from_raw_parts_mut(ptr, size as usize) };
            Ok(SendPacket {
                session: self.raw,
                ptr,
                buf,
                sent: false,
            })
        }
    }

    /// Sends a previously allocated `SendPacket`.
    ///
    /// Mirrors `WintunSendPacket`.
    pub fn send_packet(&self, mut packet: SendPacket) {
        if !packet.sent {
            wintun_send_packet(self.raw, packet.ptr);
            packet.sent = true;
        }
    }

    /// Returns the capacity of the ring buffer.
    #[inline]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Returns the raw pointer to TunSession.
    #[inline]
    pub fn raw(&self) -> *mut TunSession {
        self.raw
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            wintun_end_session(self.raw);
            self.raw = std::ptr::null_mut();
        }
    }
}

/// A received packet reference from the Wintun ring buffer.
///
/// Implements `Deref<Target = [u8]>`.
/// When dropped, it automatically calls `WintunReleaseReceivePacket` to release its slot in the ring buffer.
pub struct Packet<'a> {
    session: *mut TunSession,
    ptr: *mut u8,
    bytes: &'a [u8],
}

impl<'a> Deref for Packet<'a> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.bytes
    }
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

impl<'a> Drop for Packet<'a> {
    fn drop(&mut self) {
        wintun_release_receive_packet(self.session, self.ptr);
    }
}

/// A buffer allocated for an outgoing packet in the Wintun send ring buffer.
///
/// Implements `DerefMut<Target = [u8]>`.
pub struct SendPacket<'a> {
    session: *mut TunSession,
    ptr: *mut u8,
    buf: &'a mut [u8],
    sent: bool,
}

impl<'a> Deref for SendPacket<'a> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.buf
    }
}

impl<'a> DerefMut for SendPacket<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf
    }
}

impl<'a> SendPacket<'a> {
    /// Sends the packet through the interface.
    pub fn send(mut self) {
        if !self.sent {
            wintun_send_packet(self.session, self.ptr);
            self.sent = true;
        }
    }
}

impl<'a> Drop for SendPacket<'a> {
    fn drop(&mut self) {
        if !self.sent {
            wintun_send_packet(self.session, self.ptr);
        }
    }
}
