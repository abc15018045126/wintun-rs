#[cfg(test)]
mod unit_tests {
    use crate::types::*;

    #[test]
    fn test_alignments_and_constants() {
        assert_eq!(tun_align(0), 0);
        assert_eq!(tun_align(1), 4);
        assert_eq!(tun_align(4), 4);
        assert_eq!(tun_align(5), 8);
        assert_eq!(tun_align(65535), 65536);

        assert!(tun_is_aligned(0));
        assert!(tun_is_aligned(4));
        assert!(!tun_is_aligned(3));

        assert_eq!(tun_ring_wrap(0, 0x20000), 0);
        assert_eq!(tun_ring_wrap(0x20000, 0x20000), 0);
        assert_eq!(tun_ring_wrap(0x20004, 0x20000), 4);
    }

    #[test]
    fn test_net_luid() {
        let luid = NetLuid::new(42, 6);
        assert_eq!(luid.net_luid_index(), 42);
        assert_eq!(luid.if_type(), 6);
    }

    #[test]
    fn test_tun_packet_offsets() {
        assert_eq!(std::mem::size_of::<TunPacket>(), 4);
        let mut buffer = [0u8; 128];
        let packet_ptr = buffer.as_mut_ptr() as *mut TunPacket;
        unsafe {
            (*packet_ptr).size = 100;
            let data_ptr = TunPacket::data_ptr(packet_ptr);
            assert_eq!(data_ptr, buffer.as_mut_ptr().add(4));
            let recovered_packet = TunPacket::from_data_ptr(data_ptr);
            assert_eq!((*recovered_packet).size, 100);
        }
    }

    #[test]
    fn test_ring_descriptor_layouts() {
        assert_eq!(std::mem::size_of::<TunRing>(), 12);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(std::mem::size_of::<TunRingDescriptor>(), 24);
            assert_eq!(std::mem::size_of::<TunRegisterRings>(), 48);
        }
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(std::mem::size_of::<TunRingDescriptor>(), 12);
            assert_eq!(std::mem::size_of::<TunRegisterRings>(), 24);
        }
    }

    #[test]
    fn test_devprop_filter_layouts() {
        assert_eq!(std::mem::size_of::<DevPropKey>(), 20);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(std::mem::size_of::<DevPropCompKey>(), 32);
            assert_eq!(std::mem::size_of::<DevProperty>(), 48);
            assert_eq!(std::mem::size_of::<DevPropFilterExpression>(), 56);
            assert_eq!(std::mem::size_of::<SwDeviceCreateInfo>(), 72);
            assert_eq!(std::mem::size_of::<DevObject>(), 32);
            assert_eq!(std::mem::size_of::<DevQueryResultActionData>(), 40);
            assert_eq!(std::mem::align_of::<DevQueryResultActionData>(), 8);
            assert_eq!(DEVPROP_OPERATOR_EQUALS, 0x00000002);
            assert_eq!(DEVPROP_OPERATOR_EQUALS_IGNORE_CASE, 0x00020002);
        }
    }

    #[test]
    fn test_official_inf_constants() {
        let unix_ms = 1634083200000u64;
        let ft = unix_ms * 10000 + 116444736000000000u64;
        let low = (ft & 0xFFFFFFFF) as u32;
        let high = (ft >> 32) as u32;
        let ver = 14u64 << 32;
        assert_eq!(ver, 0x0000_000E_0000_0000);
        assert_eq!(high, 0x01D7BFC5);
        assert_eq!(low, 0x43F04000);
    }

    #[test]
    fn test_guids_and_propkeys() {
        assert_eq!(GUID_DEVCLASS_NET.data1, 0x4d36e972);
        assert_eq!(GUID_DEVCLASS_NET.data2, 0xe325);
        assert_eq!(GUID_DEVCLASS_NET.data3, 0x11ce);
        assert_eq!(
            GUID_DEVCLASS_NET.data4,
            [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18]
        );
        assert_eq!(DEVPKEY_WINTUN_NAME.pid, 3);
        assert_eq!(DEVPKEY_WINTUN_NAME.fmtid.data1, 0x3361c968);
        assert_eq!(
            DEVPKEY_WINTUN_NAME.fmtid.data4,
            [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9]
        );
    }

    #[test]
    fn test_helpers() {
        let w1: Vec<u16> = "Wintun\0".encode_utf16().collect();
        let w2: Vec<u16> = "wintun\0".encode_utf16().collect();
        let w3: Vec<u16> = "WINTUN\0".encode_utf16().collect();
        let w4: Vec<u16> = "wintun2\0".encode_utf16().collect();
        unsafe {
            assert!(wide_eq_ignore_case(w1.as_ptr(), w2.as_ptr()));
            assert!(wide_eq_ignore_case(w1.as_ptr(), w3.as_ptr()));
            assert!(!wide_eq_ignore_case(w1.as_ptr(), w4.as_ptr()));
        }
    }

    #[test]
    fn test_raii_wrappers() {
        let h = SafeHandle::null();
        assert!(h.is_null());
        assert!(!h.is_valid());
        assert_eq!(h.raw(), std::ptr::null_mut());

        let q = DevQuery::new(std::ptr::null_mut());
        assert!(q.is_null());
        assert_eq!(q.raw(), std::ptr::null_mut());

        let mut v = SafeVirtualAlloc::new(std::ptr::null_mut());
        assert!(v.is_null());
        assert_eq!(v.as_ptr(), std::ptr::null_mut());
        assert_eq!(v.take(), std::ptr::null_mut());
    }

    #[test]
    fn test_hresult_from_setupapi() {
        use crate::logger::hresult_from_setupapi;
        assert_eq!(hresult_from_setupapi(0), 0);
        // Win32 error 5 (ERROR_ACCESS_DENIED) -> 0x80070005
        assert_eq!(hresult_from_setupapi(5), 0x80070005);
        // Win32 error 2 (ERROR_FILE_NOT_FOUND) -> 0x80070002
        assert_eq!(hresult_from_setupapi(2), 0x80070002);
        // SetupAPI error 0xE000020B (SPAPI_E_NO_SUCH_DEVINST) -> 0x800F020B
        assert_eq!(hresult_from_setupapi(0xE000020B), 0x800F020B);
    }
}
