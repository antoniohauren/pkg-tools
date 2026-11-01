use super::*;

fn local_self() -> Vec<u8> {
    fn put64(b: &mut [u8], at: usize, n: u64) {
        b[at..at + 8].copy_from_slice(&n.to_be_bytes());
    }
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut b = vec![0; 704];
    b[..4].copy_from_slice(b"SCE\0");
    put32(&mut b, 4, 2);
    b[9] = 10;
    b[11] = 1;
    put32(&mut b, 12, 256);
    put64(&mut b, 16, 640);
    put64(&mut b, 40, 104);
    put32(&mut b, 116, 8);
    put64(&mut b, 88, 136);
    put64(&mut b, 96, 144);
    put32(&mut b, 136, 3);
    put32(&mut b, 140, 144);
    b[152..156].copy_from_slice(b"NPD\0");
    put32(&mut b, 160, 2);
    b[288..304].fill(1);
    b[320..336].fill(2);
    put64(&mut b, 352, 560);
    put32(&mut b, 364, 1);
    put32(&mut b, 368, 8);
    put64(&mut b, 384, 640);
    put64(&mut b, 392, 64);
    put32(&mut b, 400, 2);
    put32(&mut b, 408, 2);
    put32(&mut b, 416, 3);
    put32(&mut b, 420, 6);
    put32(&mut b, 424, 7);
    put32(&mut b, 428, 1);
    b[464..528].fill(9);
    b[528..544].fill(3);
    b[544..560].fill(4);
    b[640..].fill(42);
    let hash = hmac(&b[464..528], &b[640..]);
    b[432..452].copy_from_slice(&hash);
    ctr(&[3; 16], [4; 16], &mut b[640..]);
    ctr(&[1; 16], [2; 16], &mut b[352..640]);
    cbc(
        &hex::<32>("03c21ad78fbb6a3d425e9aab1298f9fd70e29fd4e6e3a3c151205da50c413de4"),
        hex("0a99d4d4f8301a88052d714ad2fb565e"),
        &mut b[288..352],
        false,
    );
    cbc(&aes(&KLIC, rap.key, true), [0; 16], &mut b[288..352], false);
    b
}

const OPAQUE_HEADER: usize = 0x500;
const OPAQUE_ELF: usize = 0x120;
const OPAQUE_PHDR: usize = 0x160;
const OPAQUE_MI: usize = 0x200;
const OPAQUE_MH: usize = OPAQUE_MI + 64;
const OPAQUE_TABLE: usize = OPAQUE_MH + 32;
const OPAQUE_KEYS: usize = OPAQUE_TABLE + 3 * 48;
const OPAQUE_SHDR: usize = 0x540;
const OPAQUE_AUX: usize = 0x600;
const OPAQUE_SIZE: usize = 64;
const OPAQUE_SENTINEL: &[u8; 16] = b"opaque-not-a-key";

fn self_put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_be_bytes());
}

fn opaque_metadata(b: &mut [u8]) {
    ctr(&[1; 16], [2; 16], &mut b[OPAQUE_MH..OPAQUE_HEADER]);
}

/// ELF64-BE executable with authenticated runtime/table data and stale auxiliary HMAC.
pub(crate) fn local_self_with_opaque_section() -> Vec<u8> {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut b = vec![0; OPAQUE_AUX + OPAQUE_SIZE];
    b[..4].copy_from_slice(b"SCE\0");
    put32(&mut b, 4, 2);
    b[9] = 10;
    b[11] = 1;
    put32(&mut b, 12, (OPAQUE_MI - 32) as u32);
    self_put64(&mut b, 16, OPAQUE_HEADER as u64);
    self_put64(&mut b, 24, 0x20c0);
    self_put64(&mut b, 32, 3);
    self_put64(&mut b, 40, 104);
    self_put64(&mut b, 48, OPAQUE_ELF as u64);
    self_put64(&mut b, 56, OPAQUE_PHDR as u64);
    self_put64(&mut b, 64, OPAQUE_SHDR as u64);
    self_put64(&mut b, 72, 0x198);
    self_put64(&mut b, 80, 0x1b8);
    self_put64(&mut b, 88, 136);
    self_put64(&mut b, 96, 144);
    put32(&mut b, 116, 8);
    put32(&mut b, 136, 3);
    put32(&mut b, 140, 144);
    b[152..156].copy_from_slice(b"NPD\0");
    put32(&mut b, 160, 2);

    b[OPAQUE_ELF..OPAQUE_ELF + 7].copy_from_slice(b"\x7fELF\x02\x02\x01");
    b[OPAQUE_ELF + 16..OPAQUE_ELF + 18].copy_from_slice(&2u16.to_be_bytes());
    b[OPAQUE_ELF + 18..OPAQUE_ELF + 20].copy_from_slice(&21u16.to_be_bytes());
    put32(&mut b, OPAQUE_ELF + 20, 1);
    self_put64(&mut b, OPAQUE_ELF + 24, 0x10000);
    self_put64(&mut b, OPAQUE_ELF + 32, 64);
    self_put64(&mut b, OPAQUE_ELF + 40, 0x2000);
    for (offset, value) in [(52, 64u16), (54, 56), (56, 1), (58, 64), (60, 3)] {
        b[OPAQUE_ELF + offset..OPAQUE_ELF + offset + 2].copy_from_slice(&value.to_be_bytes());
    }
    put32(&mut b, OPAQUE_PHDR, 1);
    put32(&mut b, OPAQUE_PHDR + 4, 5);
    self_put64(&mut b, OPAQUE_PHDR + 8, 0x1000);
    self_put64(&mut b, OPAQUE_PHDR + 16, 0x10000);
    self_put64(&mut b, OPAQUE_PHDR + 24, 0x10000);
    self_put64(&mut b, OPAQUE_PHDR + 32, OPAQUE_SIZE as u64);
    self_put64(&mut b, OPAQUE_PHDR + 40, OPAQUE_SIZE as u64);
    self_put64(&mut b, OPAQUE_PHDR + 48, 0x1000);
    self_put64(&mut b, 0x198, OPAQUE_HEADER as u64);
    self_put64(&mut b, 0x1a0, OPAQUE_SIZE as u64);
    put32(&mut b, 0x1a8, 1);
    self_put64(&mut b, 0x1b0, 1);
    put32(&mut b, 0x1b8, 1);
    put32(&mut b, 0x1bc, 1);
    put32(&mut b, 0x1c0, 16);

    let runtime = OPAQUE_SHDR + 64;
    let auxiliary = OPAQUE_SHDR + 128;
    put32(&mut b, runtime + 4, 1);
    self_put64(&mut b, runtime + 8, 6);
    self_put64(&mut b, runtime + 16, 0x10000);
    self_put64(&mut b, runtime + 24, 0x1000);
    self_put64(&mut b, runtime + 32, OPAQUE_SIZE as u64);
    self_put64(&mut b, runtime + 48, 16);
    put32(&mut b, auxiliary + 4, 1);
    self_put64(&mut b, auxiliary + 24, 0x1100);
    self_put64(&mut b, auxiliary + 32, OPAQUE_SIZE as u64);
    self_put64(&mut b, auxiliary + 48, 1);

    b[OPAQUE_MI..OPAQUE_MI + 16].fill(1);
    b[OPAQUE_MI + 32..OPAQUE_MI + 48].fill(2);
    self_put64(&mut b, OPAQUE_MH, (OPAQUE_KEYS + 20 * 16) as u64);
    put32(&mut b, OPAQUE_MH + 12, 3);
    put32(&mut b, OPAQUE_MH + 16, 20);
    for (i, offset, size, kind, index, hash) in [
        (0, OPAQUE_HEADER, OPAQUE_SIZE, 2, 0, 0),
        (1, OPAQUE_SHDR, 192, 1, 0, 8),
        (2, OPAQUE_AUX, OPAQUE_SIZE, 3, 2, 14),
    ] {
        let s = OPAQUE_TABLE + i * 48;
        self_put64(&mut b, s, offset as u64);
        self_put64(&mut b, s + 8, size as u64);
        put32(&mut b, s + 16, kind);
        put32(&mut b, s + 20, index);
        put32(&mut b, s + 24, 2);
        put32(&mut b, s + 28, hash);
        put32(&mut b, s + 32, 1);
        put32(&mut b, s + 44, 1);
    }
    put32(&mut b, OPAQUE_TABLE + 32, 3);
    put32(&mut b, OPAQUE_TABLE + 36, 6);
    put32(&mut b, OPAQUE_TABLE + 40, 7);
    b[OPAQUE_HEADER..OPAQUE_SHDR].fill(42);
    for chunk in b[OPAQUE_AUX..].as_chunks_mut::<16>().0 {
        chunk.copy_from_slice(OPAQUE_SENTINEL);
    }
    for (hash, offset, size) in [(0, OPAQUE_HEADER, OPAQUE_SIZE), (8, OPAQUE_SHDR, 192)] {
        let at = OPAQUE_KEYS + hash * 16;
        b[at + 32..at + 96].fill(9);
        let digest = hmac(&b[at + 32..at + 96], &b[offset..offset + size]);
        b[at..at + 20].copy_from_slice(&digest);
    }
    b[OPAQUE_KEYS + 6 * 16..OPAQUE_KEYS + 7 * 16].fill(3);
    b[OPAQUE_KEYS + 7 * 16..OPAQUE_KEYS + 8 * 16].fill(4);
    b[OPAQUE_KEYS + 14 * 16..OPAQUE_KEYS + 14 * 16 + 20].fill(0x55);
    b[OPAQUE_KEYS + 16 * 16..OPAQUE_KEYS + 20 * 16].fill(11);
    ctr(&[3; 16], [4; 16], &mut b[OPAQUE_HEADER..OPAQUE_SHDR]);
    opaque_metadata(&mut b);
    cbc(
        &hex::<32>("03c21ad78fbb6a3d425e9aab1298f9fd70e29fd4e6e3a3c151205da50c413de4"),
        hex("0a99d4d4f8301a88052d714ad2fb565e"),
        &mut b[OPAQUE_MI..OPAQUE_MH],
        false,
    );
    cbc(
        &aes(&KLIC, rap.key, true),
        [0; 16],
        &mut b[OPAQUE_MI..OPAQUE_MH],
        false,
    );
    b
}

/// Valid runtime/auxiliary HMACs with a stale section-table HMAC.
fn local_self_with_stale_table() -> Vec<u8> {
    let mut b = local_self_with_opaque_section();
    opaque_metadata(&mut b);
    let hash = OPAQUE_KEYS + 14 * 16;
    let digest = hmac(&b[hash + 32..hash + 96], &b[OPAQUE_AUX..]);
    b[hash..hash + 20].copy_from_slice(&digest);
    opaque_metadata(&mut b);
    // Change only a section-name index, leaving classification fields untouched.
    b[OPAQUE_SHDR + 64 + 3] ^= 1;
    b
}

#[test]
fn opaque_self_preserves_auxiliary_but_excludes_it_from_key_material() {
    let source = local_self_with_opaque_section();
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut output = source.clone();
    let decoded = convert_self(&mut output, &rap, &[0; 48], "EBOOT.BIN", &|| false).unwrap();
    assert_eq!(decoded, vec![vec![42; 64]]);
    assert!(
        decoded
            .iter()
            .all(|s| !s.windows(16).any(|w| w == OPAQUE_SENTINEL))
    );
    assert_eq!(&output[OPAQUE_HEADER..], &source[OPAQUE_HEADER..]);
    assert_eq!(
        &output[OPAQUE_ELF..OPAQUE_MI],
        &source[OPAQUE_ELF..OPAQUE_MI]
    );
    assert_eq!(u32_at(&output, 160).unwrap(), 3);
    assert_eq!(&output[8..10], &[0, 10]);
    let mut original_metadata = source.clone();
    opaque_metadata(&mut original_metadata);
    opaque_metadata(&mut output);
    assert_eq!(
        &output[OPAQUE_TABLE..OPAQUE_KEYS + 20 * 16],
        &original_metadata[OPAQUE_TABLE..OPAQUE_KEYS + 20 * 16]
    );
    let auxiliary_hash = OPAQUE_KEYS + 14 * 16;
    assert_ne!(
        hmac(
            &output[auxiliary_hash + 32..auxiliary_hash + 96],
            &source[OPAQUE_AUX..]
        ),
        output[auxiliary_hash..auxiliary_hash + 20]
    );
}

#[test]
fn opaque_self_never_returns_auxiliary_even_with_a_matching_hash() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    for matching_hash in [false, true] {
        let mut source = local_self_with_opaque_section();
        source[OPAQUE_AUX] ^= 1;
        if matching_hash {
            opaque_metadata(&mut source);
            let hash = OPAQUE_KEYS + 14 * 16;
            let digest = hmac(&source[hash + 32..hash + 96], &source[OPAQUE_AUX..]);
            source[hash..hash + 20].copy_from_slice(&digest);
            opaque_metadata(&mut source);
        }
        let mut output = source.clone();
        let decoded = convert_self(&mut output, &rap, &[0; 48], "EBOOT.BIN", &|| false).unwrap();
        assert_eq!(decoded, vec![vec![42; 64]]);
        assert_eq!(&output[OPAQUE_HEADER..], &source[OPAQUE_HEADER..]);
    }
}

#[test]
fn opaque_self_rejects_runtime_damage_and_stale_table_with_stale_auxiliary() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    for offset in [OPAQUE_HEADER, OPAQUE_SHDR] {
        let mut damaged = local_self_with_opaque_section();
        damaged[offset] ^= 1;
        assert!(convert_self(&mut damaged, &rap, &[0; 48], "EBOOT.BIN", &|| false).is_err());
    }
    let source = local_self_with_opaque_section();
    assert!(
        convert_self(
            &mut source.clone(),
            &Rap::from_bytes(&[8; 16]).unwrap(),
            &[0; 48],
            "EBOOT.BIN",
            &|| false
        )
        .is_err()
    );
    assert!(matches!(
        convert_self(&mut source.clone(), &rap, &[0; 48], "EBOOT.BIN", &|| true),
        Err(Error::Cancelled)
    ));
}

#[test]
fn stale_table_self_preserves_table_but_returns_only_verified_payloads() {
    let source = local_self_with_stale_table();
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut original_metadata = source.clone();
    opaque_metadata(&mut original_metadata);
    for (index, payload, matches) in [
        (0, vec![42; OPAQUE_SIZE], true),
        (8, source[OPAQUE_SHDR..OPAQUE_AUX].to_vec(), false),
        (14, source[OPAQUE_AUX..].to_vec(), true),
    ] {
        let hash = OPAQUE_KEYS + index * 16;
        assert_eq!(
            hmac(&original_metadata[hash + 32..hash + 96], &payload)
                == original_metadata[hash..hash + 20],
            matches
        );
    }
    let mut output = source.clone();
    let decoded = convert_self(&mut output, &rap, &[0; 48], "EBOOT.BIN", &|| false).unwrap();
    assert_eq!(
        decoded,
        vec![vec![42; OPAQUE_SIZE], source[OPAQUE_AUX..].to_vec()]
    );
    assert_eq!(&output[OPAQUE_HEADER..], &source[OPAQUE_HEADER..]);
    assert_eq!(
        &output[OPAQUE_ELF..OPAQUE_MI],
        &source[OPAQUE_ELF..OPAQUE_MI]
    );
    opaque_metadata(&mut output);
    assert_eq!(
        &output[OPAQUE_TABLE..OPAQUE_KEYS + 20 * 16],
        &original_metadata[OPAQUE_TABLE..OPAQUE_KEYS + 20 * 16]
    );
    for offset in [OPAQUE_HEADER, OPAQUE_AUX] {
        let mut damaged = source.clone();
        damaged[offset] ^= 1;
        assert!(matches!(
            convert_self(&mut damaged, &rap, &[0; 48], "EBOOT.BIN", &|| false),
            Err(Error::Malformed("SELF section hash mismatch"))
        ));
    }
}

#[test]
fn stale_table_self_rejects_invalid_table_role_or_hash_reference() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let table = OPAQUE_TABLE + 48;
    let auxiliary = OPAQUE_TABLE + 2 * 48;
    let mutations: &[(&str, usize, u64, usize)] = &[
        ("unhashed table", table + 24, 1, 4),
        ("truncated table key", table + 28, 15, 4),
        ("out-of-range table key", table + 28, u32::MAX as u64, 4),
        ("encrypted table", table + 32, 3, 4),
        ("compressed table", table + 44, 2, 4),
        ("wrong table type", table + 16, 3, 4),
        ("ELF program overlap", OPAQUE_PHDR + 8, 0x2000, 8),
        ("SELF segment overlap", 0x198, OPAQUE_SHDR as u64, 8),
        ("invalid segment table", 72, u64::MAX, 8),
        (
            "SELF payload overlap",
            auxiliary,
            (OPAQUE_SHDR + 16) as u64,
            8,
        ),
        ("duplicate table mapping", auxiliary, OPAQUE_SHDR as u64, 8),
        ("no runtime type 2", OPAQUE_TABLE + 16, 1, 4),
    ];
    for &(name, at, value, size) in mutations {
        let mut source = local_self_with_stale_table();
        opaque_metadata(&mut source);
        source[at..at + size].copy_from_slice(&value.to_be_bytes()[8 - size..]);
        if name == "duplicate table mapping" {
            self_put64(&mut source, auxiliary + 8, 192);
            put32(&mut source, auxiliary + 16, 1);
            put32(&mut source, auxiliary + 28, 8);
        }
        opaque_metadata(&mut source);
        assert!(
            convert_self(&mut source, &rap, &[0; 48], "EBOOT.BIN", &|| false).is_err(),
            "accepted {name}"
        );
    }
}

#[test]
fn opaque_self_keeps_plaintext_writable_runtime_authenticated() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut source = local_self_with_opaque_section();
    opaque_metadata(&mut source);
    put32(&mut source, OPAQUE_TABLE + 32, 1);
    opaque_metadata(&mut source);
    put32(&mut source, OPAQUE_PHDR + 4, 6);
    ctr(&[3; 16], [4; 16], &mut source[OPAQUE_HEADER..OPAQUE_SHDR]);
    assert!(convert_self(&mut source.clone(), &rap, &[0; 48], "EBOOT.BIN", &|| false).is_ok());
    source[OPAQUE_HEADER] ^= 1;
    assert!(convert_self(&mut source, &rap, &[0; 48], "EBOOT.BIN", &|| false).is_err());
}

#[test]
fn opaque_self_rejects_unsafe_auxiliary_classification() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let auxiliary = OPAQUE_SHDR + 128;
    let metadata = OPAQUE_TABLE + 2 * 48;
    let mutations: &[(&str, usize, u64, usize)] = &[
        ("allocated", auxiliary + 8, 2, 8),
        ("runtime address", auxiliary + 16, 0x10000, 8),
        ("program overlap", auxiliary + 24, 0x1020, 8),
        ("size mismatch", auxiliary + 32, 63, 8),
        ("not PROGBITS", auxiliary + 4, 3, 4),
        ("not ET_EXEC", OPAQUE_ELF + 16, 3, 2),
        ("bad section index", metadata + 20, 3, 4),
        ("bad hash index", metadata + 28, 20, 4),
        ("unhashed", metadata + 24, 1, 4),
        ("compressed", metadata + 44, 2, 4),
        ("encrypted", metadata + 32, 3, 4),
        (
            "metadata payload overlap",
            metadata,
            OPAQUE_HEADER as u64,
            8,
        ),
        ("header overlap", metadata, (OPAQUE_HEADER - 16) as u64, 8),
        ("section table overlap", metadata, OPAQUE_SHDR as u64, 8),
        ("bad section table pointer", 64, u64::MAX, 8),
        ("bad program table pointer", 56, u64::MAX, 8),
        ("bad ELF pointer", 48, u64::MAX, 8),
        ("ELF32", OPAQUE_ELF + 4, 1, 1),
        ("little endian", OPAQUE_ELF + 5, 1, 1),
        ("wrong machine", OPAQUE_ELF + 18, 3, 2),
        ("bad program entry size", OPAQUE_ELF + 54, 55, 2),
        ("bad section entry size", OPAQUE_ELF + 58, 63, 2),
        ("unbounded program count", OPAQUE_ELF + 56, 65535, 2),
        ("unbounded section count", OPAQUE_ELF + 60, 65535, 2),
        ("ELF section overflow", auxiliary + 24, u64::MAX, 8),
        ("ELF program overflow", OPAQUE_PHDR + 8, u64::MAX, 8),
    ];
    for &(name, at, value, size) in mutations {
        let mut b = local_self_with_opaque_section();
        opaque_metadata(&mut b);
        let bytes = value.to_be_bytes();
        b[at..at + size].copy_from_slice(&bytes[8 - size..]);
        // Reauthenticate the table so these cases exercise classification, not stale table hashes.
        let hash = OPAQUE_KEYS + 8 * 16;
        let digest = hmac(&b[hash + 32..hash + 96], &b[OPAQUE_SHDR..OPAQUE_AUX]);
        b[hash..hash + 20].copy_from_slice(&digest);
        opaque_metadata(&mut b);
        assert!(
            convert_self(&mut b, &rap, &[0; 48], "EBOOT.BIN", &|| false).is_err(),
            "accepted {name}"
        );
    }
    let source = local_self_with_opaque_section();
    for length in [103, OPAQUE_HEADER - 1, OPAQUE_SHDR + 191, source.len() - 1] {
        assert!(
            convert_self(
                &mut source[..length].to_vec(),
                &rap,
                &[0; 48],
                "EBOOT.BIN",
                &|| false
            )
            .is_err()
        );
    }
}

#[test]
fn opaque_self_rejects_overlap_with_non_load_program() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut b = local_self_with_opaque_section();
    // PT_NOTE is not loaded, but its file bytes still cannot be opaque auxiliary data.
    put32(&mut b, OPAQUE_PHDR, 4);
    self_put64(&mut b, OPAQUE_PHDR + 8, 0x1100);
    assert!(convert_self(&mut b, &rap, &[0; 48], "EBOOT.BIN", &|| false).is_err());
}

#[test]
fn revision_one_self_preserves_sections_and_rejects_wrong_rap() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut source = local_self();
    let license_key = aes(&KLIC, rap.key, true);
    cbc(&license_key, [0; 16], &mut source[288..352], true);
    cbc(
        &hex::<32>("03c21ad78fbb6a3d425e9aab1298f9fd70e29fd4e6e3a3c151205da50c413de4"),
        hex("0a99d4d4f8301a88052d714ad2fb565e"),
        &mut source[288..352],
        true,
    );
    source[9] = 1;
    cbc(
        &hex::<32>("f9edd0301f770fabba8863d9897f0fea6551b09431f61312654e28f43533ea6b"),
        hex("a551ccb4a42c37a734a2b4f9657d5540"),
        &mut source[288..352],
        false,
    );
    cbc(&license_key, [0; 16], &mut source[288..352], false);
    let mut output = source.clone();
    assert_eq!(
        convert_self(&mut output, &rap, &[0; 48], "EBOOT.BIN", &|| false).unwrap(),
        vec![vec![42; 64]]
    );
    assert_eq!(&output[640..], &source[640..]);
    assert_eq!(&output[8..10], &[0, 10]);
    assert_eq!(u32_at(&output, 160).unwrap(), 3);
    assert!(
        convert_self(
            &mut source.clone(),
            &Rap::from_bytes(&[8; 16]).unwrap(),
            &[0; 48],
            "EBOOT.BIN",
            &|| false
        )
        .is_err()
    );
    source[640] ^= 1;
    assert!(matches!(
        convert_self(&mut source, &rap, &[0; 48], "EBOOT.BIN", &|| false),
        Err(Error::Malformed("SELF section hash mismatch"))
    ));
}

#[test]
fn self_rap_rewrap_preserves_sections_and_rejects_damage() {
    let source = local_self();
    assert!(needs_license_conversion(&source[..]).unwrap());
    assert!(needs_license_conversion(&source[..103]).is_err());
    let mut labeled = source.clone();
    labeled[168..216].fill(b'A');
    assert_eq!(self_content_id(&labeled[..]).unwrap(), [b'A'; 48]);
    assert!(self_content_id(&labeled[..639]).is_err());
    labeled[140..144].copy_from_slice(&0u32.to_be_bytes());
    assert!(self_content_id(&labeled[..]).is_err());
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut output = source.clone();
    let sections = convert_self(&mut output, &rap, &[0; 48], "EBOOT.BIN", &|| false).unwrap();
    assert_eq!(sections, vec![vec![42; 64]]);
    assert_eq!(&output[640..], &source[640..]);
    assert_eq!(u32_at(&output, 160).unwrap(), 3);
    assert!(!needs_license_conversion(&output[..]).unwrap());
    cbc(
        &aes(&KLIC, FREE, true),
        [0; 16],
        &mut output[288..352],
        true,
    );
    cbc(
        &hex::<32>("03c21ad78fbb6a3d425e9aab1298f9fd70e29fd4e6e3a3c151205da50c413de4"),
        hex("0a99d4d4f8301a88052d714ad2fb565e"),
        &mut output[288..352],
        true,
    );
    assert_eq!(&output[288..304], &[1; 16]);
    assert_eq!(&output[304..320], &[0; 16]);
    for length in (0..source.len()).step_by(7) {
        assert!(
            convert_self(
                &mut source[..length].to_vec(),
                &rap,
                &[0; 48],
                "EBOOT.BIN",
                &|| false
            )
            .is_err()
        );
    }
    assert!(
        convert_self(
            &mut source.clone(),
            &Rap::from_bytes(&[8; 16]).unwrap(),
            &[0; 48],
            "EBOOT.BIN",
            &|| false
        )
        .is_err()
    );
    let mut damaged = source.clone();
    damaged[640] ^= 1;
    assert!(convert_self(&mut damaged, &rap, &[0; 48], "EBOOT.BIN", &|| false).is_err());
    let mut unsupported = source.clone();
    unsupported[9] = 0xff;
    assert!(matches!(
        convert_self(&mut unsupported, &rap, &[0; 48], "EBOOT.BIN", &|| false),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        convert_self(&mut source.clone(), &rap, &[0; 48], "EBOOT.BIN", &|| true),
        Err(Error::Cancelled)
    ));
}

pub(crate) fn local_edat(interleaved: bool) -> (Vec<u8>, Vec<u8>) {
    local_edat_version(interleaved, 3)
}

fn local_edat_version(interleaved: bool, version: u32) -> (Vec<u8>, Vec<u8>) {
    let key = Rap::from_bytes(&[7; 16]).unwrap().key;
    let wrap = hex("be959ca8308defa2e5e180c63712a9ae");
    let plain: Vec<u8> = (0..1501).map(|i| (i % 251) as u8).collect();
    let mut out = vec![0; 0x100];
    out[..4].copy_from_slice(b"NPD\0");
    put32(&mut out, 4, version);
    put32(&mut out, 8, 2);
    let mut title = vec![0; 48];
    title.extend_from_slice(b"test.edat");
    out[80..96].copy_from_slice(&cmac(&OMAC3, &title));
    let devhash = cmac(&xor(FREE, OMAC2), &out[..96]);
    out[96..112].copy_from_slice(&devhash);
    put32(&mut out, 128, if interleaved { 0x3c } else { 0x0c });
    put32(&mut out, 132, 1024);
    out[136..144].copy_from_slice(&(plain.len() as u64).to_be_bytes());
    let mut metadata = Vec::new();
    let mut payloads = Vec::new();
    for (i, part) in plain.chunks(1024).enumerate() {
        let mut seed = devhash;
        put32(&mut seed, 12, i as u32);
        let bk = aes(&key, seed, false);
        let ek = aes(&wrap, bk, true);
        let mut payload = part.to_vec();
        payload.resize(part.len().div_ceil(16) * 16, 0);
        cbc(&ek, [0; 16], &mut payload, false);
        if interleaved {
            let hk = aes(&wrap, aes(&key, bk, false), true);
            let mut hkey = [0; 20];
            hkey[..16].copy_from_slice(&hk);
            let hash = hmac(&hkey, &payload);
            let mut md = [0; 32];
            md[16..20].copy_from_slice(&hash[16..20]);
            for j in 0..16 {
                md[j] = hash[j] ^ md[j + 16];
            }
            metadata.extend_from_slice(&md);
            out.extend_from_slice(&md);
            out.extend_from_slice(&payload);
        } else {
            metadata.extend_from_slice(&cmac(&ek, &payload));
            payloads.extend_from_slice(&payload);
        }
    }
    if !interleaved {
        out.extend_from_slice(&metadata);
        out.extend_from_slice(&payloads);
    }
    out[144..160].copy_from_slice(&cmac(&aes(&wrap, key, true), &metadata));
    let hash = cmac(&aes(&wrap, key, true), &out[..160]);
    out[160..176].copy_from_slice(&hash);
    (out, plain)
}

#[test]
fn authenticated_edat_conversion_and_failures() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let wrong = Rap::from_bytes(&[8; 16]).unwrap();
    let wrap = hex("be959ca8308defa2e5e180c63712a9ae");
    for (version, interleaved) in [(2, false), (3, false), (3, true)] {
        let (input, plain) = local_edat_version(interleaved, version);
        let out = convert_edat(&input, &rap, &[0; 48], "test.edat", &[], &|| false)
            .unwrap()
            .unwrap();
        assert_eq!(u32_at(&out, 4).unwrap(), version);
        assert_eq!(u32_at(&out, 8).unwrap(), 3);
        assert!(out.ends_with(if version == 2 {
            b"EDATA 2.4.0.W\0\0\0"
        } else {
            b"EDATA 3.3.0.W\0\0\0"
        }));
        let key = aes(&wrap, FREE, true);
        assert_eq!(cmac(&key, &out[..160]), &out[160..176]);
        assert_eq!(cmac(&key, &out[256..288]), &out[144..160]);
        let mut decoded = Vec::new();
        for i in 0..2 {
            let length = 1024.min(plain.len() - i * 1024);
            let start = 288 + i * 1024;
            let end = start + length.div_ceil(16) * 16;
            let mut seed = block(&out, 96).unwrap();
            put32(&mut seed, 12, i as u32);
            let key = aes(&wrap, aes(&FREE, seed, false), true);
            let mut data = out[start..end].to_vec();
            assert_eq!(cmac(&key, &data), &out[256 + i * 16..272 + i * 16]);
            cbc(&key, block(&out, 64).unwrap(), &mut data, true);
            decoded.extend_from_slice(&data[..length]);
        }
        assert_eq!(decoded, plain);
        assert!(convert_edat(&input, &wrong, &[0; 48], "test.edat", &[], &|| false).is_err());
        assert!(convert_edat(&input, &rap, &[1; 48], "test.edat", &[], &|| false).is_err());
        assert!(convert_edat(&input, &rap, &[0; 48], "renamed.edat", &[], &|| false).is_err());
        assert!(matches!(
            convert_edat(&input, &rap, &[0; 48], "test.edat", &[], &|| true),
            Err(Error::Cancelled)
        ));
        let mut broken = input.clone();
        let end = broken.len() - 1;
        broken[end] ^= 1;
        assert!(convert_edat(&broken, &rap, &[0; 48], "test.edat", &[], &|| false).is_err());
        for length in 0..256 {
            assert!(
                convert_edat(&input[..length], &rap, &[0; 48], "test.edat", &[], &|| {
                    false
                })
                .is_err()
            );
        }
    }
    for (version, interleaved) in [(1, false), (5, false), (2, true)] {
        let (input, _) = local_edat_version(interleaved, version);
        assert!(matches!(
            convert_edat(&input, &rap, &[0; 48], "test.edat", &[], &|| false),
            Err(Error::Unsupported(_))
        ));
    }
    for length in [0, 15, 17, 32] {
        assert!(Rap::from_bytes(&vec![0; length]).is_err());
    }
}
