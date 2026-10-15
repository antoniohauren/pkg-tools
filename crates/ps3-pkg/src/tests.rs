use super::*;
use std::io::Cursor;

fn header(release: u16) -> Header {
    Header {
        release_type: release,
        platform: 1,
        metadata_offset: 0xc0,
        metadata_count: 0,
        metadata_size: 0,
        entry_count: 0,
        package_size: 0,
        data_offset: 0xc0,
        data_size: 0,
        content_id: [0; 48],
        qa_digest: std::array::from_fn(|i| i as u8),
        nonce: std::array::from_fn(|i| 240 + i as u8),
    }
}

fn cipher(release: u16) -> Package<Cursor<Vec<u8>>> {
    Package {
        reader: Cursor::new(Vec::new()),
        header: header(release),
        metadata: vec![],
        entries: vec![],
        cipher: Aes128::new(&RETAIL_KEY.into()),
    }
}

fn put32(data: &mut [u8], offset: usize, n: u32) {
    data[offset..offset + 4].copy_from_slice(&n.to_be_bytes());
}
fn put64(data: &mut [u8], offset: usize, n: u64) {
    data[offset..offset + 8].copy_from_slice(&n.to_be_bytes());
}

fn fixture(release: u16, entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let mut data = vec![0; entries.len() * 32];
    for (i, (name, flags, payload)) in entries.iter().enumerate() {
        let pos = data.len();
        put32(&mut data, i * 32, pos as u32);
        put32(&mut data, i * 32 + 4, name.len() as u32);
        data.extend_from_slice(name.as_bytes());
        let pos = data.len();
        put64(&mut data, i * 32 + 8, pos as u64);
        put64(&mut data, i * 32 + 16, payload.len() as u64);
        put32(&mut data, i * 32 + 24, *flags);
        data.extend_from_slice(payload);
    }
    let crypto = cipher(release);
    crypto.crypt(0, &mut data);
    let mut pkg = vec![0; 0xc0];
    pkg[..4].copy_from_slice(b"\x7fPKG");
    pkg[4..6].copy_from_slice(&release.to_be_bytes());
    pkg[7] = 1;
    put32(&mut pkg, 8, 0xc0);
    put32(&mut pkg, 20, entries.len() as u32);
    put64(&mut pkg, 24, 0xc0 + data.len() as u64);
    put64(&mut pkg, 32, 0xc0);
    put64(&mut pkg, 40, data.len() as u64);
    pkg[96..112].copy_from_slice(&crypto.header.qa_digest);
    pkg[112..128].copy_from_slice(&crypto.header.nonce);
    pkg.extend(data);
    pkg
}

#[test]
fn independent_crypto_vectors_and_unaligned_reads() {
    // OpenSSL AES-128-CTR and Python hashlib SHA-1, plaintext bytes 0..65.
    for (release, expected) in [
        (
            0x8000,
            "f33c60451921b63bad4ce063fcb3c3bc0ec11774bcbbddbc436e165471602c62056ebe04cc9c082713ad7fd90b3d7903c65b99591620670fa54cc85070303b1c07",
        ),
        (
            0,
            "b8873388a50e54d964725d1c9613463ef980d929e64df32bb11616ef31172d3ce0cb543bf83ad8b951381f00c758f9f4a7d42ebee5df9a9fc2455a062a165d9421",
        ),
    ] {
        let encrypted: Vec<_> = (0..expected.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
            .collect();
        for start in 0..65 {
            for end in start..=65 {
                let mut bytes = encrypted[start..end].to_vec();
                cipher(release).crypt(start as u64, &mut bytes);
                assert_eq!(bytes, (start as u8..end as u8).collect::<Vec<_>>());
            }
        }
    }
}

#[test]
fn retail_debug_trees_metadata_and_seek() {
    for release in [0, 0x8000] {
        let data: Vec<_> = (0..131089).map(|i| (i % 251) as u8).collect();
        let bytes = fixture(
            release,
            &[
                ("USRDIR/test.bin", 0x80000003, &data),
                ("USRDIR", 4, b""),
                ("empty", 2, b""),
                ("PARAM.SFO", 3, b"metadata"),
            ],
        );
        let mut pkg = Package::open(Cursor::new(bytes)).unwrap();
        assert_eq!(pkg.header().release_type, release);
        assert_eq!(pkg.entries().len(), 4);
        assert_eq!(pkg.read_param_sfo().unwrap().unwrap(), b"metadata");
        assert!(pkg.read_icon0().unwrap().is_none());
        let index = pkg
            .entries()
            .iter()
            .position(|e| e.path() == "USRDIR/test.bin")
            .unwrap();
        let mut reader = pkg.read_entry(index).unwrap();
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, data);
        for pos in [0, 1, 15, 16, 65535, 65536, 131070] {
            reader.seek(SeekFrom::Start(pos)).unwrap();
            let mut part = [0; 17];
            reader.read_exact(&mut part).unwrap();
            assert_eq!(&part, &data[pos as usize..pos as usize + 17]);
        }
        assert!(reader.seek(SeekFrom::End(1)).is_err());
        assert!(reader.seek(SeekFrom::Start(u64::MAX)).is_err());
        reader.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
        assert!(pkg.read_entry(usize::MAX).is_err());
    }
}

#[test]
fn rejects_malformed_tables_variants_and_unsafe_paths() {
    for name in [
        "",
        "/absolute",
        "../escape",
        "a/../b",
        "a//b",
        "a\\b",
        "NUL.txt",
        "end.",
        "end ",
        ".PKG-TOOLS-INCOMPLETE",
        ".pkg-tools-incomplete/file",
        "bad\0name",
        "é",
    ] {
        assert!(
            Package::open(Cursor::new(fixture(0x8000, &[(name, 3, b"x")]))).is_err(),
            "{name:?}"
        );
    }
    for (first, second) in [
        ("a", "a"),
        ("A", "a"),
        ("a", "a/b"),
        ("a/b", "a"),
        ("Dir/a", "dir/b"),
    ] {
        assert!(
            Package::open(Cursor::new(fixture(
                0,
                &[(first, 3, b"x"), (second, 3, b"x")]
            )))
            .is_err()
        );
    }
    for flags in [5, 6, 0x10000003, 0x10003, 0xff] {
        assert!(matches!(
            Package::open(Cursor::new(fixture(0, &[("file", flags, b"x")]))),
            Err(Error::Unsupported(_))
        ));
    }
    let original = fixture(0, &[("file", 3, b"hello")]);
    for len in [0, 4, 0xbf, original.len() - 1] {
        assert!(Package::open(Cursor::new(original[..len].to_vec())).is_err());
    }
    for (offset, value) in [(8, 0), (12, 1), (16, u32::MAX), (20, MAX_ENTRIES + 1)] {
        let mut bad = original.clone();
        put32(&mut bad, offset, value);
        assert!(Package::open(Cursor::new(bad)).is_err());
    }
    for field in [8, 16] {
        let mut bad = original.clone();
        cipher(0).crypt(0, &mut bad[0xc0..]);
        put64(&mut bad, 0xc0 + field, u64::MAX);
        cipher(0).crypt(0, &mut bad[0xc0..]);
        assert!(Package::open(Cursor::new(bad)).is_err());
    }
    let mut bad = original.clone();
    bad[7] = 2;
    assert!(matches!(
        Package::open(Cursor::new(bad)),
        Err(Error::Unsupported(_))
    ));
    let mut bad = original;
    bad[4] = 1;
    assert!(matches!(
        Package::open(Cursor::new(bad)),
        Err(Error::Unsupported(_))
    ));
}

#[cfg(unix)]
#[test]
fn safe_extraction_progress_cancellation_and_read_failure() {
    use std::{fs, os::unix::fs::symlink};
    let root = std::env::temp_dir().join(format!("ps3-extract-test-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let data = vec![42; 131089];
    let bytes = fixture(0x8000, &[("USRDIR/file", 9, &data), ("empty", 1, b"")]);
    let mut pkg = Package::open(Cursor::new(bytes)).unwrap();
    let out = root.join("good");
    let mut updates = Vec::new();
    pkg.extract_with_progress(&out, || false, |n, total| updates.push((n, total)))
        .unwrap();
    assert_eq!(fs::read(out.join("USRDIR/file")).unwrap(), data);
    assert_eq!(updates.first(), Some(&(0, data.len() as u64)));
    assert_eq!(
        updates.last(),
        Some(&(data.len() as u64, data.len() as u64))
    );
    assert!(updates.windows(2).all(|w| w[1].0 >= w[0].0));
    assert!(!out.join(pkg_fs::MARKER).exists());
    assert!(pkg.extract(&out).is_err());
    symlink(&out, root.join("link")).unwrap();
    assert!(pkg.extract(root.join("link/escape")).is_err());
    assert!(!out.join("escape").exists());
    assert!(matches!(
        pkg.extract_with_cancel(root.join("pre-cancel"), || true),
        Err(Error::Cancelled)
    ));
    assert!(!root.join("pre-cancel").exists());
    let cancelled = std::cell::Cell::new(false);
    let out = root.join("cancelled");
    let error = pkg
        .extract_with_progress(
            &out,
            || cancelled.get(),
            |n, _| {
                if n > 0 {
                    cancelled.set(true);
                }
            },
        )
        .unwrap_err();
    assert!(
        matches!(error, Error::IncompleteExtraction { source, .. } if matches!(*source, Error::Cancelled))
    );
    assert!(out.join(pkg_fs::MARKER).exists());
    assert_eq!(fs::metadata(out.join("USRDIR/file")).unwrap().len(), 65536);
    pkg.reader.get_mut().truncate(0xc0);
    let out = root.join("broken");
    assert!(matches!(
        pkg.extract(&out),
        Err(Error::IncompleteExtraction { .. })
    ));
    assert!(out.join(pkg_fs::MARKER).exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sparse_package_and_entry_offsets_above_four_gib() {
    struct Sparse {
        head: Vec<u8>,
        tail: Vec<u8>,
        tail_offset: u64,
        position: u64,
    }
    impl Read for Sparse {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let length = self.tail_offset + self.tail.len() as u64;
            let n = buf.len().min(length.saturating_sub(self.position) as usize);
            for (i, byte) in buf[..n].iter_mut().enumerate() {
                let pos = self.position + i as u64;
                *byte = if pos < self.head.len() as u64 {
                    self.head[pos as usize]
                } else if pos >= self.tail_offset {
                    self.tail[(pos - self.tail_offset) as usize]
                } else {
                    0
                };
            }
            self.position += n as u64;
            Ok(n)
        }
    }
    impl Seek for Sparse {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            self.position = match from {
                SeekFrom::Start(n) => n,
                SeekFrom::End(n) => (self.tail_offset + self.tail.len() as u64)
                    .checked_add_signed(n)
                    .unwrap(),
                SeekFrom::Current(n) => self.position.checked_add_signed(n).unwrap(),
            };
            Ok(self.position)
        }
    }
    for release in [0, 0x8000] {
        let mut head = fixture(release, &[("large", 3, b"")]);
        let size = (1u64 << 32) + 101;
        let start = 37;
        let tail_data = b"last sixteen!!!!";
        let tail_relative = start + size - tail_data.len() as u64;
        cipher(release).crypt(0, &mut head[0xc0..]);
        put64(&mut head, 0xc0 + 16, size);
        cipher(release).crypt(0, &mut head[0xc0..]);
        put64(&mut head, 24, 0xc0 + start + size);
        put64(&mut head, 40, start + size);
        let mut tail = tail_data.to_vec();
        cipher(release).crypt(tail_relative, &mut tail);
        let mut pkg = Package::open(Sparse {
            head,
            tail,
            tail_offset: 0xc0 + tail_relative,
            position: 0,
        })
        .unwrap();
        assert_eq!(pkg.entries()[0].size(), size);
        let mut reader = pkg.read_entry(0).unwrap();
        assert!(
            reader
                .seek(SeekFrom::End(-(tail_data.len() as i64)))
                .unwrap()
                > 1u64 << 32
        );
        let mut data = Vec::new();
        reader.read_to_end(&mut data).unwrap();
        assert_eq!(data, tail_data);
    }
}
