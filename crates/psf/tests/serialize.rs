use psf::{Entry, Error, MAX_ENTRIES, MAX_KEY_SIZE, MAX_SIZE, Sfo, Value, parse, serialize};

fn binary<'a>(key: &'a [u8], raw: &'a [u8], padding: &'a [u8]) -> Entry<'a> {
    Entry {
        key,
        format: 4,
        value: Value::Binary(raw),
        raw,
        max_len: (raw.len() + padding.len()) as u32,
        padding,
    }
}

fn model(entries: Vec<Entry<'_>>) -> Sfo<'_> {
    Sfo {
        version: 0x101,
        entries,
    }
}

#[test]
fn wire_layout_matches_checked_tables_and_zero_filled_gaps() {
    let mut unknown = binary(b"Z", b"\xfe", b"\xa5\xa6");
    unknown.format = 0x1234;
    unknown.value = Value::Unknown {
        format: 0x1234,
        bytes: b"\xfe",
    };
    let sfo = model(vec![unknown, binary(b"AB", b"\xff", b"\xbb")]);
    // Literal wire bytes check serialization without relying on our parser.
    let expected: &[u8] = &[
        0x00, 0x50, 0x53, 0x46, // Magic.
        0x01, 0x01, 0x00, 0x00, // Version 1.1.
        0x34, 0x00, 0x00, 0x00, // Key table at 52.
        0x3c, 0x00, 0x00, 0x00, // Data table at 60.
        0x02, 0x00, 0x00, 0x00, // Entry count.
        0x00, 0x00, 0x34, 0x12, // First key offset and unknown format.
        0x01, 0x00, 0x00, 0x00, // Used length.
        0x03, 0x00, 0x00, 0x00, // Capacity.
        0x00, 0x00, 0x00, 0x00, // Data offset.
        0x02, 0x00, 0x04, 0x00, // Second key offset and binary format.
        0x01, 0x00, 0x00, 0x00, // Used length.
        0x02, 0x00, 0x00, 0x00, // Capacity.
        0x04, 0x00, 0x00, 0x00, // Aligned data offset.
        b'Z', 0x00, b'A', b'B', 0x00, // Keys and terminators, in entry order.
        0x00, 0x00, 0x00, // Data table alignment gap.
        0xfe, 0xa5, 0xa6, // First raw value and retained capacity padding.
        0x00, // Second value alignment gap, outside either capacity.
        0xff, 0xbb, // Second raw value and retained capacity padding.
    ];
    assert_eq!(serialize(&sfo).unwrap(), expected);
}

#[test]
fn empty_models_and_non_utf8_bytes_are_supported() {
    let empty = serialize(&model(vec![])).unwrap();
    assert_eq!(empty.len(), 20);
    assert!(parse(&empty).unwrap().entries.is_empty());

    let mut text = binary(b"\xff", b"\xff\0tail\0", b"\xa5");
    text.format = 0x204;
    text.value = Value::Text(b"\xff");
    let mut unknown = binary(b"UNKNOWN", b"", b"\xff\0");
    unknown.format = 0x1234;
    unknown.value = Value::Unknown {
        format: 0x1234,
        bytes: b"",
    };
    let output = serialize(&model(vec![text, unknown, binary(b"EMPTY", b"", b"")])).unwrap();
    let parsed = parse(&output).unwrap();
    assert_eq!(parsed.entries[0].raw, b"\xff\0tail\0");
    assert_eq!(parsed.entries[0].padding, b"\xa5");
    assert_eq!(
        parsed.entries[1].value,
        Value::Unknown {
            format: 0x1234,
            bytes: b""
        }
    );
    assert_eq!(parsed.entries[1].padding, b"\xff\0");
    assert_eq!(parsed.entries[2].max_len, 0);
}

#[test]
fn integer_bit_patterns_survive() {
    for value in [0u32, 0x8000_0000, u32::MAX] {
        let raw = value.to_le_bytes();
        let mut entry = binary(b"INTEGER", &raw, b"\xa5");
        entry.format = 0x404;
        entry.value = Value::Integer(value);
        let output = serialize(&model(vec![entry])).unwrap();
        assert_eq!(
            parse(&output).unwrap().entries[0].value,
            Value::Integer(value)
        );
    }
}

#[test]
fn invalid_keys_versions_and_counts_fail() {
    for key in [b"".as_slice(), b"EMBEDDED\0NUL"] {
        assert!(matches!(
            serialize(&model(vec![binary(key, b"", b"")])),
            Err(Error::Malformed(_))
        ));
    }
    assert!(matches!(
        serialize(&model(vec![binary(b"A", b"", b""), binary(b"A", b"", b"")])),
        Err(Error::Malformed(_))
    ));
    let long_key = vec![b'x'; MAX_KEY_SIZE + 1];
    assert!(matches!(
        serialize(&model(vec![binary(&long_key, b"", b"")])),
        Err(Error::LimitExceeded(_))
    ));
    for version in [0x100, 0x102, u32::MAX] {
        assert_eq!(
            serialize(&Sfo {
                version,
                entries: vec![]
            }),
            Err(Error::UnsupportedVersion(version))
        );
    }
    let entries = (0..=MAX_ENTRIES).map(|_| binary(b"A", b"", b"")).collect();
    assert!(matches!(
        serialize(&model(entries)),
        Err(Error::LimitExceeded(_))
    ));
}

#[test]
fn inconsistent_models_and_missing_terminators_fail() {
    let cases = [
        Entry {
            max_len: 0,
            ..binary(b"A", b"x", b"")
        },
        Entry {
            max_len: 3,
            ..binary(b"A", b"x", b"y")
        },
        Entry {
            max_len: u32::MAX,
            ..binary(b"A", b"", b"")
        },
        Entry {
            value: Value::Binary(b"different"),
            ..binary(b"A", b"x", b"")
        },
        Entry {
            format: 0x204,
            value: Value::Text(b"x"),
            ..binary(b"A", b"x", b"\0")
        },
        Entry {
            format: 0x204,
            value: Value::Text(b"wrong"),
            ..binary(b"A", b"x\0", b"")
        },
        Entry {
            format: 0x404,
            value: Value::Integer(0),
            ..binary(b"A", b"\0\0\0", b"\0")
        },
        Entry {
            format: 0x404,
            value: Value::Integer(1),
            ..binary(b"A", b"\0\0\0\0", b"")
        },
        Entry {
            format: 0xffff,
            value: Value::Unknown {
                format: 0xfffe,
                bytes: b"x",
            },
            ..binary(b"A", b"x", b"")
        },
        Entry {
            format: 4,
            value: Value::Unknown {
                format: 4,
                bytes: b"x",
            },
            ..binary(b"A", b"x", b"")
        },
    ];
    for entry in cases {
        assert!(matches!(
            serialize(&model(vec![entry])),
            Err(Error::Malformed(_))
        ));
    }
}

#[test]
fn key_offsets_must_fit_u16_including_last_entry() {
    let mut keys: Vec<Vec<u8>> = (0..63)
        .map(|i| {
            let mut key = vec![b'x'; MAX_KEY_SIZE];
            key[..2].copy_from_slice(format!("{i:02}").as_bytes());
            key
        })
        .collect();
    keys.push(vec![b'y'; 959]);
    keys.push(b"LAST".to_vec()); // Starts at exactly u16::MAX.
    let output = serialize(&model(
        keys.iter().map(|key| binary(key, b"", b"")).collect(),
    ))
    .unwrap();
    assert_eq!(parse(&output).unwrap().entries.len(), keys.len());
    keys.push(b"TOO_FAR".to_vec());
    assert!(matches!(
        serialize(&model(
            keys.iter().map(|key| binary(key, b"", b"")).collect()
        )),
        Err(Error::LimitExceeded(_))
    ));
}

#[test]
fn output_size_limit_includes_tables_capacities_and_alignment() {
    // One index, two key bytes and two alignment bytes precede the capacity.
    let padding = vec![0xa5; MAX_SIZE - 40];
    let output = serialize(&model(vec![binary(b"A", b"", &padding)])).unwrap();
    assert_eq!(output.len(), MAX_SIZE);
    assert_eq!(parse(&output).unwrap().entries[0].padding, padding);
    assert!(matches!(
        serialize(&model(vec![binary(b"A", b"x", &padding)])),
        Err(Error::LimitExceeded(_))
    ));
    let padding = vec![0; MAX_SIZE - 61];
    // 56-byte data table, one-byte first capacity, then three alignment bytes.
    let output = serialize(&model(vec![
        binary(b"A", b"x", b""),
        binary(b"B", b"x", &padding),
    ]))
    .unwrap();
    assert_eq!(output.len(), MAX_SIZE);
    assert!(matches!(
        serialize(&model(vec![
            binary(b"A", b"xx", b""),
            binary(b"B", b"xx", &padding)
        ])),
        Err(Error::LimitExceeded(_))
    ));
}
