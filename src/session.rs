// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.

use std::sync::atomic::{fence, Ordering};
use windows_sys::Win32::Foundation::{
    CloseHandle, SetLastError, ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_INVALID_DATA,
    ERROR_NO_MORE_ITEMS, ERROR_OUTOFMEMORY, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::CreateEventW;
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::adapter::adapter_open_device_object;
use crate::logger::log_last_error;
use crate::namespace::get_security_attributes;
use crate::types::*;

pub fn wintun_start_session(adapter: *mut WintunAdapter, capacity: u32) -> *mut TunSession {
    if adapter.is_null() {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return std::ptr::null_mut();
    }

    if !(WINTUN_MIN_RING_CAPACITY..=WINTUN_MAX_RING_CAPACITY).contains(&capacity)
        || (capacity & (capacity - 1)) != 0
    {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return std::ptr::null_mut();
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
        log_last_error(&format!(
            "Failed to allocate ring memory (requested size: 0x{:x})",
            total_alloc_size
        ));
        unsafe { SetLastError(ERROR_OUTOFMEMORY) };
        return std::ptr::null_mut();
    }
    let mut allocated_region = SafeVirtualAlloc::new(raw_region);

    let sec_attr = match get_security_attributes() {
        Some(sa) => sa,
        None => {
            unsafe { SetLastError(ERROR_OUTOFMEMORY) };
            return std::ptr::null_mut();
        }
    };

    let create_session_event = |name: &str| -> Option<SafeHandle> {
        let ev = unsafe { CreateEventW(&sec_attr, 0, 0, std::ptr::null()) };
        if ev.is_null() {
            log_last_error(&format!("Failed to create {} event", name));
            None
        } else {
            Some(SafeHandle::new(ev))
        }
    };

    let Some(mut send_tail_moved) = create_session_event("send") else {
        return std::ptr::null_mut();
    };
    let Some(mut receive_tail_moved) = create_session_event("receive") else {
        return std::ptr::null_mut();
    };

    let handle_raw = unsafe { adapter_open_device_object(&*adapter) };
    if handle_raw == INVALID_HANDLE_VALUE || handle_raw.is_null() {
        return std::ptr::null_mut();
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
        log_last_error("Failed to register rings");
        return std::ptr::null_mut();
    }

    let mut session = Box::new(TunSession {
        capacity,
        receive: SessionDirectionState::default(),
        send: SessionDirectionState::default(),
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

    Box::into_raw(session)
}

pub fn wintun_end_session(session_ptr: *mut TunSession) {
    if session_ptr.is_null() {
        return;
    }

    let mut session = unsafe { Box::from_raw(session_ptr) };
    unsafe {
        DeleteCriticalSection(&mut session.send.lock);
        DeleteCriticalSection(&mut session.receive.lock);
        CloseHandle(session.handle);
        CloseHandle(session.descriptor.send.tail_moved);
        CloseHandle(session.descriptor.receive.tail_moved);
        VirtualFree(session.allocated_region as _, 0, MEM_RELEASE);
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
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return std::ptr::null_mut();
    }

    let session = unsafe { &mut *session_ptr };
    let _lock = CriticalSectionLock::new(&mut session.send.lock);

    if session.send.head_or_tail >= session.capacity {
        unsafe { SetLastError(ERROR_HANDLE_EOF) };
        return std::ptr::null_mut();
    }

    let ring = unsafe { &*session.descriptor.send.ring };
    let buff_tail = ring.tail.load(Ordering::Acquire);

    if buff_tail >= session.capacity {
        unsafe { SetLastError(ERROR_HANDLE_EOF) };
        return std::ptr::null_mut();
    }

    if session.send.head_or_tail == buff_tail {
        unsafe { SetLastError(ERROR_NO_MORE_ITEMS) };
        return std::ptr::null_mut();
    }

    let buff_content = tun_ring_wrap(
        buff_tail.wrapping_sub(session.send.head_or_tail),
        session.capacity,
    );
    if buff_content < std::mem::size_of::<TunPacket>() as u32 {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return std::ptr::null_mut();
    }

    let buff_packet = unsafe {
        (TunRing::data_ptr(session.descriptor.send.ring)).add(session.send.head_or_tail as usize)
            as *mut TunPacket
    };

    let current_size = unsafe { (*buff_packet).size };
    if current_size > WINTUN_MAX_IP_PACKET_SIZE {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return std::ptr::null_mut();
    }

    let aligned_packet_size = tun_align(std::mem::size_of::<TunPacket>() as u32 + current_size);
    if aligned_packet_size > buff_content {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return std::ptr::null_mut();
    }

    unsafe {
        *packet_size = current_size;
        session.send.head_or_tail = tun_ring_wrap(
            session.send.head_or_tail + aligned_packet_size,
            session.capacity,
        );
        session.send.packets_to_release += 1;
        TunPacket::data_ptr(buff_packet)
    }
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
                .add(session.send.head_or_tail_release as usize) as *const TunPacket
        };

        let current_size = unsafe { (*buff_packet).size };
        if (current_size & TUN_PACKET_RELEASE) == 0 {
            break;
        }

        let aligned_packet_size = tun_align(
            std::mem::size_of::<TunPacket>() as u32 + (current_size & !TUN_PACKET_RELEASE),
        );
        session.send.head_or_tail_release = tun_ring_wrap(
            session.send.head_or_tail_release + aligned_packet_size,
            session.capacity,
        );
        session.send.packets_to_release -= 1;
    }

    let ring = unsafe { &*session.descriptor.send.ring };
    ring.head
        .store(session.send.head_or_tail_release, Ordering::Release);
}

pub fn wintun_allocate_send_packet(session_ptr: *mut TunSession, packet_size: u32) -> *mut u8 {
    if session_ptr.is_null() || packet_size > WINTUN_MAX_IP_PACKET_SIZE {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return std::ptr::null_mut();
    }

    let session = unsafe { &mut *session_ptr };
    let _lock = CriticalSectionLock::new(&mut session.receive.lock);

    if session.receive.head_or_tail >= session.capacity {
        unsafe { SetLastError(ERROR_HANDLE_EOF) };
        return std::ptr::null_mut();
    }

    let aligned_packet_size = tun_align(std::mem::size_of::<TunPacket>() as u32 + packet_size);
    let ring = unsafe { &*session.descriptor.receive.ring };
    let buff_head = ring.head.load(Ordering::Acquire);

    if buff_head >= session.capacity {
        unsafe { SetLastError(ERROR_HANDLE_EOF) };
        return std::ptr::null_mut();
    }

    let buff_space = tun_ring_wrap(
        buff_head
            .wrapping_sub(session.receive.head_or_tail)
            .wrapping_sub(TUN_ALIGNMENT),
        session.capacity,
    );

    if aligned_packet_size > buff_space {
        unsafe { SetLastError(ERROR_BUFFER_OVERFLOW) };
        return std::ptr::null_mut();
    }

    let buff_packet = unsafe {
        (TunRing::data_ptr(session.descriptor.receive.ring))
            .add(session.receive.head_or_tail as usize) as *mut TunPacket
    };

    unsafe {
        (*buff_packet).size = packet_size | TUN_PACKET_RELEASE;
        session.receive.head_or_tail = tun_ring_wrap(
            session.receive.head_or_tail + aligned_packet_size,
            session.capacity,
        );
        session.receive.packets_to_release += 1;
        TunPacket::data_ptr(buff_packet)
    }
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
                .add(session.receive.head_or_tail_release as usize) as *const TunPacket
        };

        let current_size = unsafe { (*buff_packet).size };
        if (current_size & TUN_PACKET_RELEASE) != 0 {
            break;
        }

        let aligned_packet_size = tun_align(std::mem::size_of::<TunPacket>() as u32 + current_size);
        session.receive.head_or_tail_release = tun_ring_wrap(
            session.receive.head_or_tail_release + aligned_packet_size,
            session.capacity,
        );
        session.receive.packets_to_release -= 1;
    }

    let ring = unsafe { &*session.descriptor.receive.ring };
    let cur_tail = ring.tail.load(Ordering::Relaxed);
    if cur_tail != session.receive.head_or_tail_release {
        ring.tail
            .store(session.receive.head_or_tail_release, Ordering::Release);
        fence(Ordering::SeqCst);

        let alertable = ring.alertable.load(Ordering::Acquire);
        if alertable != 0 {
            unsafe { SetEvent(session.descriptor.receive.tail_moved) };
        }
    }
}
