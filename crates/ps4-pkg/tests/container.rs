use ps4_pkg::container::{
    BaseContainerLayout, DEFAULT_PLAYGO_MANIFEST, RecordSize, general_digests, header_digest,
    signature_digest,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom},
};

#[test]
#[ignore = "requires synthetic PKG from pinned check-authoring.py oracle"]
fn pinned_reference_container_layout() {
    let path = std::env::var_os("PKG_TOOLS_CONTAINER_REFERENCE")
        .expect("set PKG_TOOLS_CONTAINER_REFERENCE to the synthetic reference PKG");
    let mut source = File::open(path).unwrap();
    let mut header = [0; 0x1000];
    source.read_exact(&mut header).unwrap();
    assert_eq!(&header[..4], b"\x7fCNT");
    let u32_at = |offset| u32::from_be_bytes(header[offset..offset + 4].try_into().unwrap());
    let u64_at = |offset| u64::from_be_bytes(header[offset..offset + 8].try_into().unwrap());
    let count = u32_at(0x10) as usize;
    assert!((13..=17).contains(&count));
    let mut table = vec![0; count * 32];
    source
        .seek(SeekFrom::Start(u64::from(u32_at(0x18))))
        .unwrap();
    source.read_exact(&mut table).unwrap();
    let mut supplied = Vec::new();
    let mut names_region = None;
    for row in table.as_chunks::<32>().0 {
        let word = |offset| u32::from_be_bytes(row[offset..offset + 4].try_into().unwrap());
        let id = word(0);
        if matches!(id, 0x1000 | 0x1003 | 0x1006 | 0x1200 | 0x1220 | 0x1240) {
            supplied.push(RecordSize {
                id,
                size: u64::from(word(20)),
            });
        }
        if id == 0x200 {
            names_region = Some((word(16), word(20)));
        }
    }
    let plan = BaseContainerLayout::plan(u64_at(0x418), &supplied).unwrap();
    assert_eq!(plan.entry_table(), table);
    assert_eq!(plan.package_size(), source.metadata().unwrap().len());
    assert_eq!(plan.pfs_range().start, u64_at(0x410));
    assert_eq!(plan.body_range(), u64_at(0x20)..u64_at(0x20) + u64_at(0x28));
    let (offset, size) = names_region.expect("reference names record");
    assert_eq!(size as usize, plan.entry_names().len());
    let mut names = vec![0; size as usize];
    source.seek(SeekFrom::Start(u64::from(offset))).unwrap();
    source.read_exact(&mut names).unwrap();
    assert_eq!(plan.entry_names(), names);
    let read_record = |source: &mut File, id| {
        let entry = plan.records().iter().find(|e| e.id == id).unwrap();
        source
            .seek(SeekFrom::Start(u64::from(entry.offset)))
            .unwrap();
        let mut bytes = vec![0; entry.size as usize];
        source.read_exact(&mut bytes).unwrap();
        bytes
    };
    let dat = read_record(&mut source, 0x1001);
    let inner = u64::from_le_bytes(dat[0x158..0x160].try_into().unwrap());
    assert_eq!(
        plan.playgo_dat(std::str::from_utf8(&header[0x40..0x64]).unwrap(), inner)
            .unwrap()
            .as_slice(),
        dat
    );
    let mut sha = Vec::new();
    let pfs = plan
        .write_playgo_sha(&mut source, &mut sha, || false)
        .unwrap();
    assert_eq!(sha, read_record(&mut source, 0x1002));
    assert_eq!(pfs.image, header[0x440..0x460]);
    assert_eq!(pfs.first_block, header[0x460..0x480]);
    assert_eq!(
        plan.entry_digests(&mut source, || false).unwrap(),
        read_record(&mut source, 1)
    );
    let body = plan.body_digests(&mut source, || false).unwrap();
    assert_eq!(body.body, header[0x160..0x180]);
    assert_eq!(body.digest_table, header[0x140..0x160]);
    assert_eq!(body.sc_entries1, header[0x100..0x120]);
    assert_eq!(body.sc_entries2, header[0x120..0x140]);
    assert_eq!(
        general_digests(&header, &read_record(&mut source, 0x1000))
            .unwrap()
            .as_slice(),
        read_record(&mut source, 0x80)
    );
    assert_eq!(header_digest(&header), header[0xfe0..]);
    signature_digest(&header).unwrap();
}

const CONTENT_ID: &str = "ZZ0000-CUSA00000_00-SYNTHETIC0000000";

fn sfo(attribute2: bool) -> Vec<u8> {
    let mut values = vec![
        (
            b"ATTRIBUTE".as_slice(),
            0x404,
            0xabcdef01u32.to_le_bytes().to_vec(),
        ),
        (b"CATEGORY", 0x204, b"gd\0".to_vec()),
        (b"CONTENT_ID", 0x204, format!("{CONTENT_ID}\0").into_bytes()),
        (b"FORMAT", 0x204, b"obs\0".to_vec()),
        (b"PUBTOOLVER", 0x404, 0x02890000u32.to_le_bytes().to_vec()),
    ];
    if attribute2 {
        values.push((b"ATTRIBUTE2", 0x404, 0x123u32.to_le_bytes().to_vec()));
    }
    let entries = values
        .iter()
        .map(|(key, format, raw)| psf::Entry {
            key,
            format: *format,
            raw,
            max_len: raw.len() as u32,
            padding: &[],
            value: if *format == 0x404 {
                psf::Value::Integer(u32::from_le_bytes(raw.as_slice().try_into().unwrap()))
            } else {
                psf::Value::Text(&raw[..raw.len() - 1])
            },
        })
        .collect();
    psf::serialize(&psf::Sfo {
        version: 0x101,
        entries,
    })
    .unwrap()
}

fn plan(sfo: &[u8]) -> BaseContainerLayout {
    BaseContainerLayout::plan(
        8 * 65536,
        &[
            RecordSize {
                id: 0x1000,
                size: sfo.len() as u64,
            },
            RecordSize {
                id: 0x1003,
                size: DEFAULT_PLAYGO_MANIFEST.len() as u64,
            },
        ],
    )
    .unwrap()
}

fn put_record(bytes: &mut [u8], plan: &BaseContainerLayout, id: u32, value: &[u8]) {
    let entry = plan.records().iter().find(|e| e.id == id).unwrap();
    assert_eq!(value.len(), entry.size as usize);
    bytes[entry.offset as usize..entry.offset as usize + value.len()].copy_from_slice(value);
}

#[test]
fn keyless_synthetic_finalization() {
    let sfo = sfo(true);
    let plan = plan(&sfo);
    let mut bytes: Vec<u8> = (0..plan.package_size()).map(|i| (i % 251) as u8).collect();
    let dat = plan.playgo_dat(CONTENT_ID, 0x50000).unwrap();
    assert_eq!(&dat[0x148..0x150], &plan.package_size().to_le_bytes());
    assert_eq!(&dat[0x158..0x160], &0x50000u64.to_le_bytes());
    assert_eq!(&dat[32..64], &[0xff; 32]);
    put_record(&mut bytes, &plan, 0x1001, &dat);
    put_record(
        &mut bytes,
        &plan,
        0x1003,
        DEFAULT_PLAYGO_MANIFEST.as_bytes(),
    );
    put_record(&mut bytes, &plan, 0x1000, &sfo);
    put_record(&mut bytes, &plan, 0x100, &plan.entry_table());
    put_record(&mut bytes, &plan, 0x200, plan.entry_names());
    let mut sha = Vec::new();
    let pfs = plan
        .write_playgo_sha(&mut Cursor::new(&bytes), &mut sha, || false)
        .unwrap();
    let start = plan.pfs_range().start as usize;
    assert_eq!(
        pfs.first_block.as_slice(),
        Sha256::digest(&bytes[start..start + 65536]).as_slice()
    );
    assert_eq!(
        pfs.image.as_slice(),
        Sha256::digest(&bytes[start..]).as_slice()
    );
    assert_eq!(&sha[..start / 65536 * 4], vec![0; start / 65536 * 4]);
    for (index, block) in bytes[start..].as_chunks::<65536>().0.iter().enumerate() {
        let slot = (start / 65536 + index) * 4;
        assert_eq!(&sha[slot..slot + 4], &Sha256::digest(block)[..4]);
    }
    put_record(&mut bytes, &plan, 0x1002, &sha);
    let mut header = [0; 0x1000];
    header[..4].copy_from_slice(b"\x7fCNT");
    header[0x40..0x64].copy_from_slice(CONTENT_ID.as_bytes());
    for (offset, value) in [
        (0x10, plan.records().len() as u32),
        (0x18, 0x2a80),
        (
            0x1c,
            plan.sc_digest_ranges()[0]
                .iter()
                .map(|r| (r.end - r.start) as u32)
                .sum(),
        ),
        (0x70, 15),
        (0x74, 26),
        (0x78, 0x0a000000),
        (0x7c, start as u32),
    ] {
        header[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    header[0x14..0x16].copy_from_slice(&6u16.to_be_bytes());
    header[0x16..0x18].copy_from_slice(&(plan.records().len() as u16).to_be_bytes());
    for (offset, value) in [
        (0x20, 0x2000),
        (0x28, start as u64 - 0x2000),
        (0x410, start as u64),
        (0x418, plan.pfs_range().end - plan.pfs_range().start),
        (0x428, plan.package_size()),
        (0x430, plan.package_size()),
    ] {
        header[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    header[0x440..0x460].copy_from_slice(&pfs.image);
    header[0x460..0x480].copy_from_slice(&pfs.first_block);
    let general = general_digests(&header, &sfo).unwrap();
    let expected =
        b"ATTRIBUTE0xabcdef01ATTRIBUTE20x00000123CATEGORYgdFORMATobsPUBTOOLVER0x02890000";
    assert_eq!(&general[160..192], Sha256::digest(expected).as_slice());
    assert_eq!(&general[192..224], Sha256::digest(&sfo).as_slice());
    assert_eq!(&general[128..160], &[0; 32]);
    assert_eq!(&general[224..], &[0; 160]);
    put_record(&mut bytes, &plan, 0x80, &general);
    let digests = plan
        .entry_digests(&mut Cursor::new(&bytes), || false)
        .unwrap();
    assert_eq!(&digests[..32], &[0; 32]);
    let mut records: Vec<_> = plan.records().iter().collect();
    records.sort_by_key(|e| e.id);
    for (index, e) in records.iter().enumerate().skip(1) {
        assert_eq!(
            &digests[index * 32..index * 32 + 32],
            Sha256::digest(&bytes[e.offset as usize..e.offset as usize + e.size as usize])
                .as_slice()
        );
    }
    put_record(&mut bytes, &plan, 1, &digests);
    let body = plan
        .body_digests(&mut Cursor::new(&bytes), || false)
        .unwrap();
    assert_eq!(
        body.body.as_slice(),
        Sha256::digest(&bytes[0x2000..start]).as_slice()
    );
    for (ids, truncate, expected) in [
        (&[0x10, 0x20, 0x80, 0x100, 1][..], false, body.sc_entries1),
        (&[0x10, 0x20, 0x80, 0x100][..], true, body.sc_entries2),
    ] {
        let mut input = Vec::new();
        for id in ids {
            let e = plan.records().iter().find(|e| e.id == *id).unwrap();
            let len = if truncate && *id == 0x100 {
                6 * 32
            } else {
                e.size as usize
            };
            input.extend_from_slice(&bytes[e.offset as usize..e.offset as usize + len]);
        }
        assert_eq!(expected.as_slice(), Sha256::digest(input).as_slice());
    }
    for (offset, value) in [
        (0x100, body.sc_entries1),
        (0x120, body.sc_entries2),
        (0x140, body.digest_table),
        (0x160, body.body),
    ] {
        header[offset..offset + 32].copy_from_slice(&value);
    }
    // General header coverage excludes later body/SC hash fields.
    assert_eq!(general_digests(&header, &sfo).unwrap(), general);
    assert!(signature_digest(&header).is_err());
    let hash = header_digest(&header);
    header[0xfe0..].copy_from_slice(&hash);
    assert_eq!(
        signature_digest(&header).unwrap().as_slice(),
        Sha256::digest(header).as_slice()
    );
    bytes[..0x1000].copy_from_slice(&header);
    // Explicit opt-in export: opaque test bytes, NOT a valid package/writer.
    if let Some(path) = std::env::var_os("PKG_TOOLS_KEYLESS_SYNTHETIC_OUTPUT") {
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        output.write_all(&bytes).unwrap();
    }
    bytes[start - 1] ^= 1;
    let changed = plan
        .body_digests(&mut Cursor::new(&bytes), || false)
        .unwrap();
    assert_ne!(changed.body, body.body);
    assert_eq!(changed.sc_entries1, body.sc_entries1);
    assert_eq!(
        plan.entry_digests(&mut Cursor::new(&bytes), || false)
            .unwrap(),
        digests
    );
}

struct ShortReader {
    data: Cursor<Vec<u8>>,
    limit: usize,
    eof: Option<u64>,
}
impl Read for ShortReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.eof.is_some_and(|end| self.data.position() >= end) {
            return Ok(0);
        }
        let count = bytes.len().min(self.limit);
        self.data.read(&mut bytes[..count])
    }
}
impl Seek for ShortReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.data.seek(pos)
    }
}

#[test]
fn streaming_boundaries_short_reads_cancellation_and_errors() {
    let plan = plan(&sfo(false));
    let data = vec![7; plan.package_size() as usize];
    let mut expected = Vec::new();
    plan.write_playgo_sha(&mut Cursor::new(&data), &mut expected, || false)
        .unwrap();
    let mut source = ShortReader {
        data: Cursor::new(data),
        limit: 17,
        eof: None,
    };
    let mut actual = Vec::new();
    plan.write_playgo_sha(&mut source, &mut actual, || false)
        .unwrap();
    assert_eq!(actual, expected);
    source.eof = Some(plan.pfs_range().start + 65536 - 1);
    assert_eq!(
        plan.write_playgo_sha(&mut source, &mut Vec::new(), || false)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    source.eof = None;
    let mut calls = 0;
    let mut partial = Vec::new();
    assert_eq!(
        plan.write_playgo_sha(&mut source, &mut partial, || {
            calls += 1;
            calls > 100
        })
        .err()
        .unwrap()
        .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        partial,
        vec![0; plan.pfs_range().start as usize / 65536 * 4]
    );
    assert_eq!(
        plan.entry_digests(&mut source, || true).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        plan.body_digests(&mut source, || true)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Interrupted
    );
    for length in [plan.package_size() - 1, plan.package_size() + 1] {
        assert_eq!(
            plan.write_playgo_sha(
                &mut Cursor::new(vec![0; length as usize]),
                &mut Vec::new(),
                || false
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(
        plan.write_playgo_sha(&mut source, &mut Cursor::new(&mut [0u8; 1][..]), || false)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WriteZero
    );
    for inner in [0, 1, 65535, plan.package_size(), u64::MAX] {
        assert!(plan.playgo_dat(CONTENT_ID, inner).is_err());
    }
    assert!(plan.playgo_dat("invalid", 65536).is_err());
}

#[test]
fn general_digests_reject_wrong_types_identity_and_missing_fields() {
    let mut header = [0; 0x1000];
    header[..4].copy_from_slice(b"\x7fCNT");
    header[0x40..0x64].copy_from_slice(CONTENT_ID.as_bytes());
    header[0x70..0x74].copy_from_slice(&15u32.to_be_bytes());
    header[0x74..0x78].copy_from_slice(&26u32.to_be_bytes());
    let bytes = sfo(false);
    let valid = general_digests(&header, &bytes).unwrap();
    assert_eq!(
        &valid[160..192],
        Sha256::digest(b"ATTRIBUTE0xabcdef01CATEGORYgdFORMATobsPUBTOOLVER0x02890000").as_slice()
    );
    header[0x440] ^= 1;
    let changed = general_digests(&header, &bytes).unwrap();
    assert_ne!(&changed[32..128], &valid[32..128]);
    assert_eq!(&changed[160..224], &valid[160..224]);
    header[0x440] ^= 1;
    for key in [
        b"ATTRIBUTE".as_slice(),
        b"CATEGORY",
        b"CONTENT_ID",
        b"FORMAT",
        b"PUBTOOLVER",
    ] {
        let mut parsed = psf::parse(&bytes).unwrap();
        parsed.entries.retain(|e| e.key != key);
        assert!(general_digests(&header, &psf::serialize(&parsed).unwrap()).is_err());
    }
    let mut wrong = bytes.clone();
    // Integer with valid binary encoding is still wrong type, not a default.
    wrong[22..24].copy_from_slice(&4u16.to_le_bytes());
    assert!(general_digests(&header, &wrong).is_err());
    let optional = sfo(true);
    let mut parsed = psf::parse(&optional).unwrap();
    let entry = parsed
        .entries
        .iter_mut()
        .find(|e| e.key == b"ATTRIBUTE2")
        .unwrap();
    entry.format = 4;
    entry.value = psf::Value::Binary(entry.raw);
    assert!(general_digests(&header, &psf::serialize(&parsed).unwrap()).is_err());
    header[0x40] ^= 1;
    assert!(general_digests(&header, &bytes).is_err());
    assert!(general_digests(&header, b"bad").is_err());
}
