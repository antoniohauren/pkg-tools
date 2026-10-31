use psf::{Error, Value, parse};

fn fixture() -> Vec<u8> {
    let fields: &[(&[u8], u16, &[u8], u32)] = &[
        (b"TITLE", 0x204, b"Example\0", 12),
        (b"ATTRIBUTE", 0x404, &[0xff; 4], 4),
        (b"BINARY", 4, &[0, 0xff, 1], 4),
        (b"FUTURE", 0xffff, &[0xfe, 0], 2),
        (b"EMPTY", 4, &[], 0),
    ];
    let mut data = vec![0; 20 + fields.len() * 16];
    data[..4].copy_from_slice(b"\0PSF");
    put(&mut data, 4, 0x101);
    put(&mut data, 8, (20 + fields.len() * 16) as u32);
    put(&mut data, 16, fields.len() as u32);
    let mut key_offset = 0u16;
    let mut value_offset = 0;
    for (i, (key, format, value, capacity)) in fields.iter().enumerate() {
        let record = 20 + i * 16;
        data[record..record + 2].copy_from_slice(&key_offset.to_le_bytes());
        data[record + 2..record + 4].copy_from_slice(&format.to_le_bytes());
        put(&mut data, record + 4, value.len() as u32);
        put(&mut data, record + 8, *capacity);
        put(&mut data, record + 12, value_offset);
        data.extend_from_slice(key);
        data.push(0);
        key_offset += key.len() as u16 + 1;
        value_offset += capacity;
    }
    let values = data.len() as u32;
    put(&mut data, 12, values);
    for (_, _, value, capacity) in fields {
        data.extend_from_slice(value);
        data.resize(data.len() + *capacity as usize - value.len(), 0xaa);
    }
    data
}
fn put(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn typed_values_and_unknown_bytes_survive() {
    let mut data = fixture();
    for version in [0x100, 0x101] {
        put(&mut data, 4, version);
        let sfo = parse(&data).unwrap();
        assert_eq!(sfo.version, version);
        let title = sfo.get(b"TITLE").unwrap();
        assert_eq!(title.value, Value::Text(b"Example"));
        assert_eq!(title.raw, b"Example\0");
        assert_eq!(title.padding, &[0xaa; 4]);
        assert_eq!(
            sfo.get(b"ATTRIBUTE").unwrap().value,
            Value::Integer(u32::MAX)
        );
        assert_eq!(
            sfo.get(b"BINARY").unwrap().value,
            Value::Binary(&[0, 255, 1])
        );
        assert_eq!(
            sfo.get(b"FUTURE").unwrap().value,
            Value::Unknown {
                format: 65535,
                bytes: &[254, 0]
            }
        );
        assert_eq!(sfo.get(b"EMPTY").unwrap().raw, b"");
    }
}

#[test]
fn every_truncation_fails() {
    let data = fixture();
    for end in 0..data.len() {
        assert!(parse(&data[..end]).is_err(), "accepted length {end}");
    }
}

#[test]
fn invalid_tables_lengths_and_aliases_fail() {
    for (offset, value) in [
        (8, 0),
        (8, u32::MAX),
        (12, 0),
        (12, u32::MAX),
        (16, u32::MAX),
        (24, 13),
        (28, u32::MAX),
        (32, u32::MAX),
        (40, 3), // Integer width.
        (48, 0), // Aliased value range.
    ] {
        let mut data = fixture();
        put(&mut data, offset, value);
        assert!(
            matches!(parse(&data), Err(Error::Malformed(_))),
            "offset {offset}"
        );
    }
    let mut data = fixture();
    put(&mut data, 4, 0x102);
    assert_eq!(parse(&data).unwrap_err(), Error::UnsupportedVersion(0x102));
}

#[test]
fn terminators_duplicates_and_non_utf8() {
    let original = fixture();
    let values = u32::from_le_bytes(original[12..16].try_into().unwrap()) as usize;
    let mut data = original.clone();
    data[values + 7] = b'x';
    assert!(parse(&data).is_err());
    let mut data = original.clone();
    data[36..38].fill(0);
    assert!(parse(&data).is_err());
    let mut data = original.clone();
    data[100..values].fill(b'x');
    assert!(parse(&data).is_err());
    let mut data = original;
    data[values] = 0xff;
    assert!(matches!(
        parse(&data).unwrap().entries[0].value,
        Value::Text(_)
    ));
}

#[test]
fn hostile_counts_and_sizes_are_bounded() {
    let mut long_key = vec![b'x'; 36 + psf::MAX_KEY_SIZE + 2];
    long_key[..4].copy_from_slice(b"\0PSF");
    put(&mut long_key, 4, 0x101);
    put(&mut long_key, 8, 36);
    let end = long_key.len() as u32;
    put(&mut long_key, 12, end);
    put(&mut long_key, 16, 1);
    long_key[20..36].fill(0);
    *long_key.last_mut().unwrap() = 0;
    assert!(matches!(parse(&long_key), Err(Error::LimitExceeded(_))));

    let mut data = vec![0; 20 + (psf::MAX_ENTRIES + 1) * 16];
    data[..4].copy_from_slice(b"\0PSF");
    put(&mut data, 4, 0x101);
    let len = data.len() as u32;
    put(&mut data, 8, len);
    put(&mut data, 12, len);
    put(&mut data, 16, psf::MAX_ENTRIES as u32 + 1);
    assert!(matches!(parse(&data), Err(Error::LimitExceeded(_))));
    data.resize(psf::MAX_SIZE + 1, 0);
    assert!(matches!(parse(&data), Err(Error::LimitExceeded(_))));
}

#[test]
fn deterministic_mutations_never_panic() {
    let original = fixture();
    for i in 0..original.len() {
        for byte in [0, 0x7f, 0xff] {
            let mut data = original.clone();
            data[i] = byte;
            let _ = parse(&data);
        }
    }
}

#[test]
fn serialize_reparse_preserves_semantics_not_layout() {
    let mut source = fixture(); // Deliberately unaligned data table and values.
    source.extend_from_slice(b"unretained trailing bytes");
    let parsed = parse(&source).unwrap();
    let output = psf::serialize(&parsed).unwrap();
    assert_ne!(output, source);
    let reparsed = parse(&output).unwrap();
    assert_eq!(reparsed.version, parsed.version);
    assert_eq!(reparsed.entries.len(), parsed.entries.len());
    for (before, after) in parsed.entries.iter().zip(&reparsed.entries) {
        assert_eq!(before.key, after.key);
        assert_eq!(before.format, after.format);
        assert_eq!(before.value, after.value);
        assert_eq!(before.raw, after.raw);
        assert_eq!(before.max_len, after.max_len);
        assert_eq!(before.padding, after.padding);
    }
    assert_eq!(psf::serialize(&reparsed).unwrap(), output);
    assert_eq!(
        u32::from_le_bytes(output[12..16].try_into().unwrap()) % 4,
        0
    );
    for i in 0..parsed.entries.len() {
        let offset = 32 + i * 16;
        assert_eq!(
            u32::from_le_bytes(output[offset..offset + 4].try_into().unwrap()) % 4,
            0
        );
    }
}

#[test]
fn parsed_mutations_serialize_without_panics() {
    let original = fixture();
    for i in 0..original.len() {
        for byte in [0, 0x7f, 0xff] {
            let mut data = original.clone();
            data[i] = byte;
            if let Ok(sfo) = parse(&data) {
                if sfo.version != 0x101 {
                    assert_eq!(
                        psf::serialize(&sfo),
                        Err(Error::UnsupportedVersion(sfo.version))
                    );
                    continue;
                }
                let output = psf::serialize(&sfo).unwrap();
                assert!(parse(&output).is_ok());
            }
        }
    }
}
