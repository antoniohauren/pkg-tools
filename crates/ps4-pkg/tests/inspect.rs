use ps4_pkg::{Error, Package};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

fn put32(data: &mut [u8], offset: usize, n: u32) {
    data[offset..offset + 4].copy_from_slice(&n.to_be_bytes());
}
fn put64(data: &mut [u8], offset: usize, n: u64) {
    data[offset..offset + 8].copy_from_slice(&n.to_be_bytes());
}
fn fixture() -> Vec<u8> {
    let mut data = vec![0; 0x1200];
    data[..4].copy_from_slice(b"\x7fCNT");
    put32(&mut data, 0x10, 1);
    put32(&mut data, 0x18, 0x1100);
    put64(&mut data, 0x430, 0x1200);
    put32(&mut data, 0x1100, 0x1000);
    put32(&mut data, 0x1110, 0x1120);
    put32(&mut data, 0x1114, 16);
    data[0x1120..0x1130].copy_from_slice(b"raw SFO content!");
    data
}

#[test]
fn metadata_and_encryption_status() {
    let mut data = fixture();
    let mut pkg = Package::open(Cursor::new(&data)).unwrap();
    assert_eq!(pkg.header().entry_count, 1);
    assert_eq!(pkg.read_param_sfo().unwrap().unwrap(), b"raw SFO content!");
    put32(&mut data, 0x1108, 0x8000_0000);
    put32(&mut data, 0x110c, 0x3000);
    let mut pkg = Package::open(Cursor::new(data)).unwrap();
    assert!(matches!(
        pkg.read_param_sfo(),
        Err(Error::DecryptionUnavailable {
            entry_id: 0x1000,
            key_index: 3
        })
    ));
}

#[test]
fn missing_sfo_and_ps3_are_distinct() {
    let mut data = fixture();
    put32(&mut data, 0x1100, 0x1200);
    assert!(
        Package::open(Cursor::new(&data))
            .unwrap()
            .read_param_sfo()
            .unwrap()
            .is_none()
    );
    data[..4].copy_from_slice(b"\x7fPKG");
    assert!(matches!(
        Package::open(Cursor::new(data)),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn all_truncations_and_overflowed_ranges_fail() {
    let data = fixture();
    for end in 0..data.len() {
        assert!(Package::open(Cursor::new(&data[..end])).is_err());
    }
    for (offset, value) in [
        (0x10, u32::MAX),
        (0x18, u32::MAX),
        (0x1110, u32::MAX),
        (0x1114, u32::MAX),
    ] {
        let mut data = fixture();
        put32(&mut data, offset, value);
        assert!(matches!(
            Package::open(Cursor::new(data)),
            Err(Error::Malformed(_))
        ));
    }
    for offset in [0x20, 0x410, 0x420] {
        let mut data = fixture();
        put64(&mut data, offset, u64::MAX);
        put64(&mut data, offset + 8, 1);
        assert!(matches!(
            Package::open(Cursor::new(data)),
            Err(Error::Malformed(_))
        ));
    }
}

#[test]
fn duplicate_ids_fail_but_unaligned_encrypted_lengths_are_inspectable() {
    let mut data = fixture();
    put32(&mut data, 0x10, 2);
    data.copy_within(0x1100..0x1120, 0x1120);
    assert!(matches!(
        Package::open(Cursor::new(data)),
        Err(Error::Malformed(_))
    ));
    let mut data = fixture();
    put32(&mut data, 0x1108, 0x8000_0000);
    put32(&mut data, 0x1114, 15);
    assert!(matches!(
        Package::open(Cursor::new(data)).unwrap().read_param_sfo(),
        Err(Error::DecryptionUnavailable { .. })
    ));
}

// Virtual sparse input exercises >4 GiB offsets without allocating its payload.
struct Sparse {
    header: Cursor<Vec<u8>>,
    len: u64,
    read: usize,
    fail: bool,
}
impl Seek for Sparse {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::End(0) => {
                self.header.set_position(self.len);
                Ok(self.len)
            }
            _ => self.header.seek(pos),
        }
    }
}
impl Read for Sparse {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.fail {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected"));
        }
        self.read += out.len().min(3);
        // Force short reads even for valid data.
        let len = out.len().min(3);
        self.header.read(&mut out[..len])
    }
}

#[test]
fn large_package_uses_only_header_and_table_reads() {
    let mut data = fixture();
    let len = (1u64 << 33) + 0x1000;
    put64(&mut data, 0x430, len);
    put64(&mut data, 0x410, 1u64 << 32);
    put64(&mut data, 0x418, 1u64 << 32);
    let mut reader = Sparse {
        header: Cursor::new(data),
        len,
        read: 0,
        fail: false,
    };
    let pkg = Package::open(&mut reader).unwrap();
    assert_eq!(pkg.header().package_size, len);
    assert!(reader.read < 2048);
    reader.fail = true;
    assert!(
        matches!(Package::open(reader), Err(Error::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn resource_limits_checked_before_allocation() {
    let mut data = fixture();
    let len = 1u64 << 33;
    put64(&mut data, 0x430, len);
    put32(&mut data, 0x10, ps4_pkg::MAX_ENTRIES + 1);
    let reader = Sparse {
        header: Cursor::new(data),
        len,
        read: 0,
        fail: false,
    };
    assert!(matches!(
        Package::open(reader),
        Err(Error::LimitExceeded(_))
    ));
    let mut data = fixture();
    put64(&mut data, 0x430, len);
    put32(&mut data, 0x1114, ps4_pkg::MAX_SFO_SIZE + 1);
    let reader = Sparse {
        header: Cursor::new(data),
        len,
        read: 0,
        fail: false,
    };
    assert!(matches!(
        Package::open(reader).unwrap().read_param_sfo(),
        Err(Error::LimitExceeded(_))
    ));
}
