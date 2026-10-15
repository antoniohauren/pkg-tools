use super::*;

pub(crate) fn convert(
    b: &[u8],
    rap: &Rap,
    cid: &[u8; 48],
    name: &str,
    sections: &[Vec<u8>],
    cancel: &impl Fn() -> bool,
) -> Result<Option<Vec<u8>>, Error> {
    span(b, 0, 0x100)?;
    if &b[..4] != b"NPD\0" {
        return Err(Error::Malformed("EDAT NPD magic"));
    }
    let flags = u32_at(b, 0x80)?;
    if flags & 0x01000000 != 0 || u32_at(b, 8)? == 3 {
        return Ok(None);
    }
    if u32_at(b, 8)? != 2 || u32_at(b, 12)? != 0 || !matches!(flags, 0x0c | 0x3c) {
        return Err(Error::Unsupported(
            "EDAT: only local-license common, uncompressed 0x0C/0x3C is convertible",
        ));
    }
    if &b[16..64] != cid {
        return Err(Error::Unsupported(
            "EDAT needs a different content ID / RAP",
        ));
    }
    let version = u32_at(b, 4)?;
    let wrap = match version {
        3 => hex("be959ca8308defa2e5e180c63712a9ae"),
        4 => hex("4ca9c14b01c95309969bec68aa0bc081"),
        _ => return Err(Error::Unsupported("EDAT version (supported: 3, 4)")),
    };
    let header_key = aes(&wrap, rap.key, true);
    if cmac(&header_key, &b[..0xa0]) != b[0xa0..0xb0] {
        return Err(Error::Malformed(
            "EDAT header hash mismatch; wrong RAP or damaged EDAT",
        ));
    }
    let mut title = cid.to_vec();
    title.extend_from_slice(name.as_bytes());
    if cmac(&OMAC3, &title) != b[80..96] {
        return Err(Error::Malformed("EDAT filename/content hash mismatch"));
    }
    let matches = |k: &[u8; 16]| cmac(&xor(*k, OMAC2), &b[..96]) == b[96..112];
    let mut devkey = [FREE, rap.key, [0; 16]].into_iter().find(matches);
    if devkey.is_none() {
        'search: for section in sections {
            for (i, window) in section.windows(16).enumerate() {
                if i.is_multiple_of(4096) {
                    check_cancel(cancel)?;
                }
                let key: [u8; 16] = window.try_into().unwrap();
                if matches(&key) {
                    devkey = Some(key);
                    break 'search;
                }
            }
        }
    }
    let devkey = devkey.ok_or(Error::Unsupported(
        "EDAT developer key not found in decoded SELF sections",
    ))?;
    let block_size = u32_at(b, 0x84)? as usize;
    if !matches!(block_size, 1024 | 2048 | 4096 | 8192 | 16384 | 32768) {
        return Err(Error::Unsupported("EDAT block size"));
    }
    let size = u64_at(b, 0x88)?;
    if size > MAX_FILE {
        return Err(Error::LimitExceeded("EDAT plaintext size"));
    }
    let count = (size as usize).div_ceil(block_size);
    let meta_size = if flags == 0x3c { 32 } else { 16 };
    let mut metadata = Vec::with_capacity(count * meta_size);
    let mut plain = Vec::with_capacity(size as usize);
    for i in 0..count {
        check_cancel(cancel)?;
        let (mo, offset) = if flags == 0x3c {
            let mo = 0x100 + i * (32 + block_size);
            (mo, mo + 32)
        } else {
            (0x100 + i * 16, 0x100 + count * 16 + i * block_size)
        };
        let mr = span(b, mo as u64, meta_size as u64)?;
        let md = &b[mr];
        metadata.extend_from_slice(md);
        let length = block_size.min(size as usize - i * block_size);
        let r = span(b, offset as u64, length.div_ceil(16) as u64 * 16)?;
        let mut data = b[r].to_vec();
        let mut seed = block(b, 96)?;
        put32(&mut seed, 12, i as u32);
        let bk = aes(&rap.key, seed, false);
        let ek = aes(&wrap, bk, true);
        let hk = aes(
            &wrap,
            if flags == 0x3c {
                aes(&rap.key, bk, false)
            } else {
                bk
            },
            true,
        );
        if flags == 0x3c {
            let mut expected = [0; 20];
            expected.copy_from_slice(&md[..20]);
            for j in 0..16 {
                expected[j] ^= md[j + 16];
            }
            let mut key = [0; 20];
            key[..16].copy_from_slice(&hk);
            if hmac(&key, &data) != expected {
                return Err(Error::Malformed("EDAT block hash mismatch"));
            }
        } else if cmac(&hk, &data) != md {
            return Err(Error::Malformed("EDAT block hash mismatch"));
        }
        cbc(&ek, block(b, 64)?, &mut data, true);
        plain.extend_from_slice(&data[..length]);
    }
    if cmac(&header_key, &metadata) != b[0x90..0xa0] {
        return Err(Error::Malformed("EDAT metadata hash mismatch"));
    }
    let mut out = vec![0; 0x100 + count * 16 + (size as usize).div_ceil(16) * 16];
    out[..0x90].copy_from_slice(&b[..0x90]);
    put32(&mut out, 8, 3);
    put32(&mut out, 0x80, 0x0c);
    let devhash = cmac(&xor(devkey, OMAC2), &out[..96]);
    out[96..112].copy_from_slice(&devhash);
    for (i, part) in plain.chunks(block_size).enumerate() {
        check_cancel(cancel)?;
        let offset = 0x100 + count * 16 + i * block_size;
        let end = offset + part.len().div_ceil(16) * 16;
        out[offset..offset + part.len()].copy_from_slice(part);
        let mut seed = devhash;
        put32(&mut seed, 12, i as u32);
        let key = aes(&wrap, aes(&devkey, seed, false), true);
        cbc(&key, block(b, 64)?, &mut out[offset..end], false);
        let hash = cmac(&key, &out[offset..end]);
        out[0x100 + i * 16..0x110 + i * 16].copy_from_slice(&hash);
    }
    let key = aes(&wrap, devkey, true);
    let hash = cmac(&key, &out[0x100..0x100 + count * 16]);
    out[0x90..0xa0].copy_from_slice(&hash);
    let hash = cmac(&key, &out[..0xa0]);
    out[0xa0..0xb0].copy_from_slice(&hash);
    // Common EDAT uses CMAC authentication; PS2/disc-bound signature formats are rejected.
    out.extend_from_slice(if version == 3 {
        b"EDATA 3.3.0.W\0\0\0"
    } else {
        b"EDATA 4.0.0.W\0\0\0"
    });
    Ok(Some(out))
}
