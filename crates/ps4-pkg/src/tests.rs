use super::*;
use crate::{
    input::{ReadAt, Shared},
    pfs::{BLOCK, Pfs},
    pfsc::Pfsc,
};
use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io::{Cursor, Write},
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

fn u16le(b: &mut [u8], p: usize, n: u16) {
    b[p..p + 2].copy_from_slice(&n.to_le_bytes());
}
fn u32le(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn u64le(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
fn u32be(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_be_bytes());
}
fn u64be(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_be_bytes());
}
fn memory(bytes: Vec<u8>) -> Shared<Cursor<Vec<u8>>> {
    Shared {
        size: bytes.len() as u64,
        reader: Rc::new(RefCell::new(Cursor::new(bytes))),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}

fn pfs_header(b: &mut [u8], signed: bool, inodes: u64) {
    u64le(b, 0, 1);
    u64le(b, 8, 20130315);
    u16le(b, 0x1c, if signed { 9 } else { 8 });
    u32le(b, 0x20, BLOCK as u32);
    u64le(b, 0x28, 1);
    u64le(b, 0x30, inodes);
    u64le(b, 0x40, 1);
}
fn inode(b: &mut [u8], signed: bool, n: usize, dir: bool, size: u64, start: u32) {
    let width = if signed { 0x2c8 } else { 0xa8 };
    let p = BLOCK as usize + n * width;
    u16le(b, p, if dir { 0x416d } else { 0x816d });
    u64le(b, p + 8, size);
    u64le(b, p + 16, size);
    u32le(b, p + 96, size.div_ceil(BLOCK) as u32);
    for i in 0..17 {
        u32le(
            b,
            p + if signed { 132 + i * 36 } else { 100 + i * 4 },
            u32::MAX,
        );
    }
    u32le(b, p + if signed { 132 } else { 100 }, start);
}
fn dir(b: &mut [u8], block: usize, entries: &[(&str, u32, u32)]) {
    let mut p = block * BLOCK as usize;
    for &(name, ino, kind) in entries {
        let size = (name.len() + 17).div_ceil(8) * 8;
        u32le(b, p, ino);
        u32le(b, p + 4, kind);
        u32le(b, p + 8, name.len() as u32);
        u32le(b, p + 12, size as u32);
        b[p + 16..p + 16 + name.len()].copy_from_slice(name.as_bytes());
        p += size;
    }
}
fn payload() -> Vec<u8> {
    (0..65537)
        .map(|i| ((i * 17 + i / 113) % 251) as u8)
        .collect()
}
fn inner() -> Vec<u8> {
    let mut b = vec![0; 7 * BLOCK as usize];
    pfs_header(&mut b, false, 5);
    inode(&mut b, false, 0, true, BLOCK, 2);
    inode(&mut b, false, 1, true, BLOCK, 3);
    inode(&mut b, false, 2, false, 65537, 4);
    inode(&mut b, false, 3, true, BLOCK, 6);
    inode(&mut b, false, 4, false, 0, 0);
    dir(&mut b, 2, &[("uroot", 1, 3)]);
    dir(
        &mut b,
        3,
        &[
            (".", 1, 4),
            ("..", 0, 5),
            ("eboot.bin", 2, 2),
            ("empty-dir", 3, 3),
            ("empty", 4, 2),
        ],
    );
    dir(&mut b, 6, &[(".", 3, 4), ("..", 1, 5)]);
    b[4 * BLOCK as usize..4 * BLOCK as usize + 65537].copy_from_slice(&payload());
    b
}
fn pfsc(raw: &[u8]) -> Vec<u8> {
    let count = raw.len() / BLOCK as usize;
    let start = 48 + (count + 1) * 8;
    let mut b = vec![0; start];
    b[..4].copy_from_slice(b"PFSC");
    u32le(&mut b, 8, 6);
    u32le(&mut b, 12, BLOCK as u32);
    u64le(&mut b, 16, BLOCK);
    u64le(&mut b, 24, 48);
    u64le(&mut b, 32, start as u64);
    u64le(&mut b, 40, raw.len() as u64);
    for (i, chunk) in raw.chunks(BLOCK as usize).enumerate() {
        let pos = b.len() as u64;
        u64le(&mut b, 48 + i * 8, pos);
        if i % 2 == 0 {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(chunk).unwrap();
            let z = z.finish().unwrap();
            assert!(z.len() < BLOCK as usize);
            b.extend_from_slice(&z);
        } else {
            b.extend_from_slice(chunk);
        }
    }
    let pos = b.len() as u64;
    u64le(&mut b, 48 + count * 8, pos);
    b
}
fn cbc_encrypt(b: &mut [u8], key: &[u8], iv: &[u8]) {
    let len = b.len();
    cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded::<NoPadding>(b, len)
        .unwrap();
}
fn package(raw: Vec<u8>) -> Vec<u8> {
    let compressed = pfsc(&raw);
    let blocks = 4 + compressed.len().div_ceil(BLOCK as usize);
    let mut outer = vec![0; blocks * BLOCK as usize];
    pfs_header(&mut outer, true, 3);
    inode(&mut outer, true, 0, true, BLOCK, 2);
    inode(&mut outer, true, 1, true, BLOCK, 3);
    inode(&mut outer, true, 2, false, compressed.len() as u64, 4);
    dir(&mut outer, 2, &[("uroot", 1, 3)]);
    dir(&mut outer, 3, &[("pfs_image.dat", 2, 2)]);
    outer[4 * BLOCK as usize..4 * BLOCK as usize + compressed.len()].copy_from_slice(&compressed);
    let key = [0x42; 32];
    let dk3 = [0x24; 32];
    let seed = [0x13; 16];
    u16le(&mut outer, 0x1c, 13);
    outer[0x370..0x380].copy_from_slice(&seed);
    let mut covered = [0; 0x5a0];
    covered[..0x380].copy_from_slice(&outer[..0x380]);
    let mac = crypto::hmac(&crypto::pfs_material(&key, &seed, 2), &covered);
    outer[0x380..0x3a0].copy_from_slice(&mac);
    crypto::xts(&crypto::pfs_material(&key, &seed, 1)).encrypt_area(
        &mut outer[BLOCK as usize..],
        4096,
        16,
        xts_mode::get_tweak_default,
    );
    let mut b = vec![0; BLOCK as usize];
    b[..4].copy_from_slice(b"\x7fCNT");
    u32be(&mut b, 0x10, 3);
    u32be(&mut b, 0x18, 0x1100);
    u32be(&mut b, 0x74, 0x1a);
    u64be(&mut b, 0x408, 0xa000000000000000);
    u64be(&mut b, 0x410, BLOCK);
    u64be(&mut b, 0x418, outer.len() as u64);
    let image = Entry {
        id: 0x20,
        name_offset: 0,
        flags1: 0x80000000,
        flags2: 0x3000,
        offset: 0x2800,
        size: 256,
    };
    for (i, e) in [
        Entry {
            id: 0x10,
            name_offset: 0,
            flags1: 0,
            flags2: 0,
            offset: 0x2000,
            size: 2048,
        },
        image.clone(),
        Entry {
            id: 0x1000,
            name_offset: 0,
            flags1: 0,
            flags2: 0,
            offset: 0x2900,
            size: 3,
        },
    ]
    .iter()
    .enumerate()
    {
        for (j, v) in [e.id, e.name_offset, e.flags1, e.flags2, e.offset, e.size]
            .iter()
            .enumerate()
        {
            u32be(&mut b, 0x1100 + i * 32 + j * 4, *v);
        }
    }
    for (index, value) in [(1, key), (3, dk3)] {
        let hash = Sha256::digest(value);
        for j in 0..32 {
            b[0x2000 + 32 + index * 32 + j] = hash[j] ^ value[j];
        }
    }
    let wrapped = rsa::RsaPublicKey::from(crypto::rsa_key(false))
        .encrypt(&mut rsa::rand_core::OsRng, rsa::Pkcs1v15Encrypt, &dk3)
        .unwrap();
    b[0x2400..0x2500].copy_from_slice(&wrapped);
    let mut wrapped = rsa::RsaPublicKey::from(crypto::rsa_key(true))
        .encrypt(&mut rsa::rand_core::OsRng, rsa::Pkcs1v15Encrypt, &key)
        .unwrap();
    let m = crypto::entry_material(&image, &dk3);
    cbc_encrypt(&mut wrapped, &m[16..], &m[..16]);
    b[0x2800..0x2900].copy_from_slice(&wrapped);
    b[0x2900..0x2903].copy_from_slice(b"SFO");
    b.extend_from_slice(&outer);
    let len = b.len() as u64;
    u64be(&mut b, 0x430, len);
    b
}

#[test]
fn nested_encrypted_streaming_and_seek() {
    let mut game = Package::open(Cursor::new(package(inner())))
        .unwrap()
        .open_game()
        .unwrap();
    assert_eq!(game.entries().len(), 5);
    let index = game
        .entries()
        .iter()
        .position(|e| e.path() == "eboot.bin")
        .unwrap();
    let mut reader = game.read_entry(index).unwrap();
    reader.seek(SeekFrom::Start(65530)).unwrap();
    let mut cross = [0; 7];
    reader.read_exact(&mut cross).unwrap();
    assert_eq!(cross, payload()[65530..]);
    assert_eq!(reader.read(&mut cross).unwrap(), 0);
    assert!(reader.seek(SeekFrom::End(1)).is_err());
    reader.rewind().unwrap();
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, payload());
}

#[test]
fn crypto_known_answers() {
    // Pinned LibOrbisPkg XtsDecryptReader, reproduced by reference --self-test.
    let mut sector: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    crypto::xts(&crypto::pfs_material(&[0x42; 32], &[0x13; 16], 1)).decrypt_area(
        &mut sector,
        4096,
        16,
        xts_mode::get_tweak_default,
    );
    assert_eq!(
        hex(&Sha256::digest(&sector)),
        "b18421326c7c7e311df6397fc380170e3bdb61a63ae5ed97aeb74e577821dc5d"
    );
    assert_eq!(
        hex(&crypto::hmac(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let mut data = unhex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");
    crypto::cbc_decrypt(
        &mut data,
        &unhex("2b7e151628aed2a6abf7158809cf4f3c"),
        &unhex("000102030405060708090a0b0c0d0e0f"),
    )
    .unwrap();
    assert_eq!(
        hex(&data),
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    );
}

#[test]
fn corrupt_keys_header_and_variants() {
    let base = package(inner());
    for (offset, value) in [(0x2400, 1), (0x2800, 1), (BLOCK as usize + 0x370, 1)] {
        let mut b = base.clone();
        b[offset] ^= value;
        assert!(Package::open(Cursor::new(b)).unwrap().open_game().is_err());
    }
    let mut b = base.clone();
    u32be(&mut b, 0x74, 0x1e);
    assert!(matches!(
        Package::open(Cursor::new(b)).unwrap().open_game(),
        Err(Error::Unsupported(_))
    ));
    let mut b = base;
    u32be(&mut b, 0x1100 + 32 + 12, 0x2000);
    assert!(matches!(
        Package::open(Cursor::new(b)).unwrap().open_game(),
        Err(Error::DecryptionUnavailable { .. })
    ));
}

#[test]
fn malformed_pfs_directories_and_modes() {
    for mutation in 0..6 {
        let mut b = inner();
        match mutation {
            0 => u16le(&mut b, 0x1c, 10),
            1 => u32le(&mut b, 3 * BLOCK as usize + 12, 8),
            2 => {
                b[3 * BLOCK as usize + 16] = b'/';
            }
            3 => u32le(&mut b, 2 * BLOCK as usize, 9000),
            4 => u16le(&mut b, BLOCK as usize + 2 * 0xa8, 0xa16d),
            _ => u64le(&mut b, BLOCK as usize + 2 * 0xa8 + 8, u64::MAX),
        }
        assert!(
            Package::open(Cursor::new(package(b)))
                .unwrap()
                .open_game()
                .is_err(),
            "mutation {mutation}"
        );
    }
    let mut b = inner();
    b[3 * BLOCK as usize..4 * BLOCK as usize].fill(0);
    dir(&mut b, 3, &[("loop", 1, 3)]);
    assert!(matches!(
        Package::open(Cursor::new(package(b))).unwrap().open_game(),
        Err(Error::Malformed("PFS directory cycle/alias"))
    ));
}

#[test]
fn pfsc_checks_offsets_checksum_and_exact_length() {
    let original = pfsc(&inner());
    for mutation in 0..4 {
        let mut b = original.clone();
        match mutation {
            0 => u64le(&mut b, 56, 0),
            1 => u64le(&mut b, 48, u64::MAX),
            2 => {
                let end = input::le64(&b, 56) as usize;
                b[end - 1] ^= 1;
            }
            _ => u64le(&mut b, 40, u64::MAX),
        }
        let result = Pfsc::open(memory(b)).and_then(|mut p| p.read_at(0, &mut [0; 16]));
        assert!(result.is_err());
    }
}

#[test]
fn signed_direct_single_double_indirection_and_large_offsets() {
    // A sparse synthetic backing store exercises >4 GiB without allocating it.
    struct Sparse {
        header: Vec<u8>,
        high: u64,
    }
    impl ReadAt for Sparse {
        fn len(&self) -> u64 {
            self.high + BLOCK
        }
        fn read_at(&mut self, offset: u64, b: &mut [u8]) -> Result<(), Error> {
            range(offset, b.len() as u64, self.len())?;
            b.fill(0);
            if offset < self.header.len() as u64 {
                b.copy_from_slice(&self.header[offset as usize..offset as usize + b.len()]);
            } else if offset >= self.high {
                b.fill(0x5a);
            }
            Ok(())
        }
    }
    let refs = BLOCK / 36;
    let count = 12 + refs + 2;
    let high = 0x1_0001_0000;
    let mut b = vec![0; 6 * BLOCK as usize];
    pfs_header(&mut b, true, 1);
    inode(&mut b, true, 0, false, count * BLOCK, 2);
    for i in 0..12 {
        u32le(&mut b, BLOCK as usize + 132 + i * 36, (high / BLOCK) as u32);
    }
    u32le(&mut b, BLOCK as usize + 132 + 12 * 36, 3);
    u32le(&mut b, BLOCK as usize + 132 + 13 * 36, 4);
    for i in 0..refs as usize {
        u32le(
            &mut b,
            3 * BLOCK as usize + i * 36 + 32,
            (high / BLOCK) as u32,
        );
    }
    u32le(&mut b, 4 * BLOCK as usize + 32, 5);
    for i in 0..2 {
        u32le(
            &mut b,
            5 * BLOCK as usize + i * 36 + 32,
            (high / BLOCK) as u32,
        );
    }
    let mut p = Pfs::open(
        Sparse {
            header: b.clone(),
            high,
        },
        None,
    )
    .unwrap();
    let file = p.inode(0).unwrap();
    for block in [0, 11, 12, 12 + refs - 1, 12 + refs, 12 + refs + 1] {
        let mut out = [0; 3];
        p.read_file(&file, block * BLOCK + 4095, &mut out).unwrap();
        assert_eq!(out, [0x5a; 3]);
    }
    u32le(&mut b, 5 * BLOCK as usize + 32, u32::MAX);
    let mut p = Pfs::open(Sparse { header: b, high }, None).unwrap();
    let bad = p.inode(0).unwrap();
    assert!(p.read_file(&bad, (12 + refs) * BLOCK, &mut [0; 1]).is_err());

    // Contiguous logical file exceeds 4 GiB too; seek directly to its tail.
    let mut b = vec![0; 2 * BLOCK as usize];
    pfs_header(&mut b, false, 1);
    inode(&mut b, false, 0, false, 0x1_0000_0001, 2);
    let mut p = Pfs::open(
        Sparse {
            header: b,
            high: 0x1_0002_0000,
        },
        None,
    )
    .unwrap();
    let large = p.inode(0).unwrap();
    let mut tail = [0; 1];
    p.read_file(&large, 0x1_0000_0000, &mut tail).unwrap();
    assert_eq!(tail, [0x5a]);
}

#[cfg(unix)]
fn temp() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let p = std::env::temp_dir().join(format!(
        "pkg-tools-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&p).unwrap();
    p
}
#[cfg(unix)]
#[test]
fn extraction_no_overwrite_symlink_escape_or_invisible_failure() {
    let bytes = package(inner());
    let mut game = Package::open(Cursor::new(bytes.clone()))
        .unwrap()
        .open_game()
        .unwrap();
    let temp = temp();
    let output = temp.join("out");
    game.extract(&output).unwrap();
    assert_eq!(std::fs::read(output.join("eboot.bin")).unwrap(), payload());
    assert!(output.join("empty-dir").is_dir());
    assert_eq!(
        std::fs::read(output.join("sce_sys/param.sfo")).unwrap(),
        b"SFO"
    );
    assert!(!output.join(".pkg-tools-incomplete").exists());
    assert!(game.extract(&output).is_err());
    std::os::unix::fs::symlink(&output, temp.join("link")).unwrap();
    assert!(game.extract(temp.join("link/new")).is_err());
    assert!(!output.join("new").exists());
    // Fail after enumeration: an input I/O error must leave a visible marker.
    struct Shrinking {
        data: Cursor<Vec<u8>>,
        fail: Rc<RefCell<bool>>,
    }
    impl Read for Shrinking {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            if *self.fail.borrow() {
                Err(io::Error::other("injected read failure"))
            } else {
                self.data.read(b)
            }
        }
    }
    impl Seek for Shrinking {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.data.seek(p)
        }
    }
    let fail = Rc::new(RefCell::new(false));
    let mut broken = Package::open(Shrinking {
        data: Cursor::new(bytes),
        fail: Rc::clone(&fail),
    })
    .unwrap()
    .open_game()
    .unwrap();
    *fail.borrow_mut() = true;
    let dest = temp.join("broken");
    assert!(matches!(
        broken.extract(&dest),
        Err(Error::IncompleteExtraction { .. })
    ));
    assert!(dest.join(".pkg-tools-incomplete").exists());
    std::fs::remove_dir_all(temp).unwrap();
}
