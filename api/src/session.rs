use std::sync::atomic::{fence, Ordering};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_OUTOFMEMORY, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows_sys::Win32::System::Threading::CreateEventW;
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::adapter::adapter_open_device_object;
use crate::logger::{is_logger_active, log_last_error, log_msg};
use crate::namespace::get_security_attributes;
use crate::types::*;

fn wintun_start_session_inner(
    adapter: *mut WintunAdapter,
    capacity: u32,
) -> Result<*mut TunSession, u32> {
    if adapter.is_null() {
        return Err(ERROR_INVALID_DATA);
    }

    let ring_size = tun_ring_size(capacity);
    let total_alloc_size = (ring_size as usize) * 2;

    let raw_region = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            total_alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8
    };

    if raw_region.is_null() {
        let last_err = get_last_error();
        if is_logger_active() {
            log_last_error(&format!(
                "Failed to allocate ring memory (requested size: 0x{:x})",
                total_alloc_size
            ));
        }
        return Err(last_err);
    }
    let mut allocated_region = SafeVirtualAlloc::new(raw_region);

    let sec_attr = match get_security_attributes() {
        Some(sa) => sa,
        None => {
            return Err(ERROR_OUTOFMEMORY);
        }
    };

    let send_tail_ev = unsafe { CreateEventW(&sec_attr, 0, 0, std::ptr::null()) };
    if send_tail_ev.is_null() {
        return Err(log_last_error("Failed to create send event"));
    }
    let mut send_tail_moved = SafeHandle::new(send_tail_ev);

    let receive_tail_ev = unsafe { CreateEventW(&sec_attr, 0, 0, std::ptr::null()) };
    if receive_tail_ev.is_null() {
        return Err(log_last_error("Failed to create receive event"));
    }
    let mut receive_tail_moved = SafeHandle::new(receive_tail_ev);

    let handle_raw = unsafe { adapter_open_device_object(&*adapter) };
    if handle_raw == INVALID_HANDLE_VALUE || handle_raw.is_null() {
        log_msg(
            WintunLoggerLevel::Err,
            "Failed to open adapter device object",
        );
        return Err(get_last_error());
    }
    let mut handle = SafeHandle::new(handle_raw);

    let send_ring = allocated_region.as_ptr() as *mut TunRing;
    let receive_ring = unsafe { allocated_region.as_ptr().add(ring_size as usize) as *mut TunRing };

    let descriptor = TunRegisterRings {
        send: TunRingDescriptor {
            ring_size,
            ring: send_ring,
            tail_moved: send_tail_moved.raw(),
        },
        receive: TunRingDescriptor {
            ring_size,
            ring: receive_ring,
            tail_moved: receive_tail_moved.raw(),
        },
    };

    let mut bytes_returned: u32 = 0;
    let ioctl_res = unsafe {
        DeviceIoControl(
            handle.raw(),
            TUN_IOCTL_REGISTER_RINGS,
            &descriptor as *const _ as *const _,
            std::mem::size_of::<TunRegisterRings>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if ioctl_res == 0 {
        return Err(log_last_error("Failed to register rings"));
    }

    let mut session = Box::new(TunSession {
        capacity,
        receive: SessionReceiveState::default(),
        send: SessionSendState::default(),
        descriptor: TunRegisterRings {
            send: TunRingDescriptor {
                ring_size,
                ring: send_ring,
                tail_moved: send_tail_moved.take(),
            },
            receive: TunRingDescriptor {
                ring_size,
                ring: receive_ring,
                tail_moved: receive_tail_moved.take(),
            },
        },
        handle: handle.take(),
        allocated_region: allocated_region.take(),
    });

    unsafe {
        InitializeCriticalSectionAndSpinCount(&mut session.receive.lock, LOCK_SPIN_COUNT);
        InitializeCriticalSectionAndSpinCount(&mut session.send.lock, LOCK_SPIN_COUNT);
    }

    Ok(Box::into_raw(session))
}

pub fn wintun_start_session(adapter: *mut WintunAdapter, capacity: u32) -> *mut TunSession {
    match wintun_start_session_inner(adapter, capacity) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

pub fn wintun_end_session(session_ptr: *mut TunSession) {
    if !session_ptr.is_null() {
        drop(unsafe { Box::from_raw(session_ptr) });
    }
}

pub fn wintun_get_read_wait_event(session_ptr: *mut TunSession) -> HANDLE {
    if session_ptr.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { (*session_ptr).descriptor.send.tail_moved }
}

pub fn wintun_receive_packet(session_ptr: *mut TunSession, packet_size: *mut u32) -> *mut u8 {
    if session_ptr.is_null() || packet_size.is_null() {
        set_last_error(ERROR_INVALID_DATA);
        return std::ptr::null_mut();
    }

    let session = unsafe { &mut *session_ptr };
    let lock = CriticalSectionLock::new(&mut session.send.lock);

    if session.send.head >= session.capacity {
        drop(lock);
        set_last_error(ERROR_HANDLE_EOF);
        return std::ptr::null_mut();
    }

    let ring = unsafe { &*session.descriptor.send.ring };
    let buff_tail = ring.tail.load(Ordering::Acquire);

    if buff_tail >= session.capacity {
        drop(lock);
        set_last_error(ERROR_HANDLE_EOF);
        return std::ptr::null_mut();
    }

    if session.send.head == buff_tail {
        drop(lock);
        set_last_error(ERROR_NO_MORE_ITEMS);
        return std::ptr::null_mut();
    }

    let buff_content = tun_ring_wrap(buff_tail.wrapping_sub(session.send.head), session.capacity);
    if buff_content < std::mem::size_of::<TunPacket>() as u32 {
        drop(lock);
        set_last_error(ERROR_INVALID_DATA);
        return std::ptr::null_mut();
    }

    let buff_packet = unsafe {
        (TunRing::data_ptr(session.descriptor.send.ring)).add(session.send.head as usize)
            as *mut TunPacket
    };

    let current_size = unsafe { (*buff_packet).size };
    if current_size > WINTUN_MAX_IP_PACKET_SIZE {
        drop(lock);
        set_last_error(ERROR_INVALID_DATA);
        return std::ptr::null_mut();
    }

    let aligned_packet_size = tun_align(std::mem::size_of::<TunPacket>() as u32 + current_size);
    if aligned_packet_size > buff_content {
        drop(lock);
        set_last_error(ERROR_INVALID_DATA);
        return std::ptr::null_mut();
    }

    unsafe { *packet_size = current_size };
    session.send.head = tun_ring_wrap(session.send.head + aligned_packet_size, session.capacity);
    session.send.packets_to_release += 1;
    drop(lock);
    unsafe { TunPacket::data_ptr(buff_packet) }
}

pub fn wintun_release_receive_packet(session_ptr: *mut TunSession, packet: *const u8) {
    if session_ptr.is_null() || packet.is_null() {
        return;
    }

    let session = unsafe { &mut *session_ptr };
    let _lock = CriticalSectionLock::new(&mut session.send.lock);

    let released_buff_packet = unsafe { TunPacket::from_data_ptr(packet) };
    unsafe {
        (*released_buff_packet).size |= TUN_PACKET_RELEASE;
    }

    while session.send.packets_to_release > 0 {
        let buff_packet = unsafe {
            (TunRing::data_ptr(session.descriptor.send.ring))
                .add(session.send.head_release as usize) as *const TunPacket
        };

        let current_size = unsafe { (*buff_packet).size };
        if (current_size & TUN_PACKET_RELEASE) == 0 {
            break;
        }

        let aligned_packet_size = tun_align(
            std::mem::size_of::<TunPacket>() as u32 + (current_size & !TUN_PACKET_RELEASE),
        );
        session.send.head_release = tun_ring_wrap(
            session.send.head_release + aligned_packet_size,
            session.capacity,
        );
        session.send.packets_to_release -= 1;
    }

    let ring = unsafe { &*session.descriptor.send.ring };
    ring.head
        .store(session.send.head_release, Ordering::Release);
}

pub fn wintun_allocate_send_packet(session_ptr: *mut TunSession, packet_size: u32) -> *mut u8 {
    if session_ptr.is_null() {
        set_last_error(ERROR_INVALID_DATA);
        return std::ptr::null_mut();
    }

    let session = unsafe { &mut *session_ptr };
    let lock = CriticalSectionLock::new(&mut session.receive.lock);

    if session.receive.tail >= session.capacity {
        drop(lock);
        set_last_error(ERROR_HANDLE_EOF);
        return std::ptr::null_mut();
    }

    let aligned_packet_size = tun_align(std::mem::size_of::<TunPacket>() as u32 + packet_size);
    let ring = unsafe { &*session.descriptor.receive.ring };
    let buff_head = ring.head.load(Ordering::Acquire);

    if buff_head >= session.capacity {
        drop(lock);
        set_last_error(ERROR_HANDLE_EOF);
        return std::ptr::null_mut();
    }

    let buff_space = tun_ring_wrap(
        buff_head
            .wrapping_sub(session.receive.tail)
            .wrapping_sub(TUN_ALIGNMENT),
        session.capacity,
    );

    if aligned_packet_size > buff_space {
        drop(lock);
        set_last_error(ERROR_BUFFER_OVERFLOW);
        return std::ptr::null_mut();
    }

    let buff_packet = unsafe {
        (TunRing::data_ptr(session.descriptor.receive.ring)).add(session.receive.tail as usize)
            as *mut TunPacket
    };

    unsafe {
        (*buff_packet).size = packet_size | TUN_PACKET_RELEASE;
    }
    session.receive.tail =
        tun_ring_wrap(session.receive.tail + aligned_packet_size, session.capacity);
    session.receive.packets_to_release += 1;
    drop(lock);
    unsafe { TunPacket::data_ptr(buff_packet) }
}

pub fn wintun_send_packet(session_ptr: *mut TunSession, packet: *const u8) {
    if session_ptr.is_null() || packet.is_null() {
        return;
    }

    let session = unsafe { &mut *session_ptr };
    let _lock = CriticalSectionLock::new(&mut session.receive.lock);

    let released_buff_packet = unsafe { TunPacket::from_data_ptr(packet) };
    unsafe {
        (*released_buff_packet).size &= !TUN_PACKET_RELEASE;
    }

    while session.receive.packets_to_release > 0 {
        let buff_packet = unsafe {
            (TunRing::data_ptr(session.descriptor.receive.ring))
                .add(session.receive.tail_release as usize) as *const TunPacket
        };

        let current_size = unsafe { (*buff_packet).size };
        if (current_size & TUN_PACKET_RELEASE) != 0 {
            break;
        }

        let aligned_packet_size = tun_align(std::mem::size_of::<TunPacket>() as u32 + current_size);
        session.receive.tail_release = tun_ring_wrap(
            session.receive.tail_release + aligned_packet_size,
            session.capacity,
        );
        session.receive.packets_to_release -= 1;
    }

    let ring = unsafe { &*session.descriptor.receive.ring };
    let cur_tail = ring.tail.load(Ordering::Relaxed);
    if cur_tail != session.receive.tail_release {
        ring.tail
            .store(session.receive.tail_release, Ordering::Release);
        fence(Ordering::SeqCst);

        let alertable = ring.alertable.load(Ordering::Acquire);
        if alertable != 0 {
            unsafe { SetEvent(session.descriptor.receive.tail_moved) };
        }
    }
}
