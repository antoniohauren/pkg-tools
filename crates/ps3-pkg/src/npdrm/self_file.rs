use super::*;
use std::io::Read;

const OUTPUT_ERK: [u8; 32] =
    hex("03c21ad78fbb6a3d425e9aab1298f9fd70e29fd4e6e3a3c151205da50c413de4");
const OUTPUT_IV: [u8; 16] = hex("0a99d4d4f8301a88052d714ad2fb565e");

fn npd_offset(b: &[u8]) -> Result<Option<usize>, Error> {
    span(b, 0, 104)?;
    if &b[..4] != b"SCE\0" || u32_at(b, 4)? != 2 || b[10..12] != [0, 1] {
        return Err(Error::Unsupported("SELF header"));
    }
    let header_len = u64_at(b, 16)?;
    if header_len > 16 * 1024 * 1024 {
        return Err(Error::LimitExceeded("SELF header"));
    }
    span(b, 0, header_len)?;
    let ai = u64_at(b, 40)?;
    let info = span(&b[..header_len as usize], ai, 32)?;
    if u32_at(b, info.start + 12)? != 8 {
        return Ok(None);
    }
    let ci_start = u64_at(b, 88)?;
    let ci_size = u64_at(b, 96)?;
    let cis = span(&b[..header_len as usize], ci_start, ci_size)?;
    let mut cursor = cis.start;
    let mut npd = None;
    while cursor < cis.end {
        span(&b[..cis.end], cursor as u64, 16)?;
        let kind = u32_at(b, cursor)?;
        let size = u32_at(b, cursor + 4)? as usize;
        if size < 16 {
            return Err(Error::Malformed("SELF control record size"));
        }
        span(&b[..cis.end], cursor as u64, size as u64)?;
        if kind == 3 {
            if size != 144 || npd.is_some() {
                return Err(Error::Malformed("SELF NPDRM control record"));
            }
            npd = Some(cursor + 16);
        }
        cursor += size;
    }
    let npd = npd.ok_or(Error::Malformed("SELF NPDRM control record missing"))?;
    if &b[npd..npd + 4] != b"NPD\0" {
        return Err(Error::Malformed("SELF NPD magic"));
    }
    Ok(Some(npd))
}

fn read_header(mut reader: impl Read) -> Result<Vec<u8>, Error> {
    let mut prefix = [0; 104];
    reader.read_exact(&mut prefix)?;
    let length = u64_at(&prefix, 16)?;
    if !(104..=16 * 1024 * 1024).contains(&length) {
        return Err(Error::LimitExceeded("SELF header"));
    }
    let mut header = vec![0; length as usize];
    header[..104].copy_from_slice(&prefix);
    reader.read_exact(&mut header[104..])?;
    Ok(header)
}

pub(crate) fn needs_license_conversion(reader: impl Read) -> Result<bool, Error> {
    let header = read_header(reader)?;
    let Some(offset) = npd_offset(&header)? else {
        return Ok(false);
    };
    Ok(u32_at(&header, offset + 8)? != 3)
}

/// Read the NPDRM content ID from a SELF header without decrypting its payload.
pub fn self_content_id(reader: impl Read) -> Result<[u8; 48], Error> {
    let header = read_header(reader)?;
    let offset = npd_offset(&header)?.ok_or(Error::Unsupported("SELF is not NPDRM"))?;
    Ok(header[offset + 16..offset + 64].try_into().unwrap())
}

const METADATA_SECTION_SIZE: usize = 48;
const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_SIZE: usize = 56;
const ELF64_SECTION_SIZE: usize = 64;
const SELF_SEGMENT_SIZE: usize = 32;

// Classify before decoding: auxiliary bytes are preserved, never EDAT key material.
fn opaque_sections(
    b: &[u8],
    header_len: usize,
    metadata_info: usize,
    table: Range<usize>,
    key_count: usize,
    verify_hash: impl Fn(usize, &[u8]) -> Result<bool, Error>,
    cancel: &impl Fn() -> bool,
) -> Result<Vec<bool>, Error> {
    let count = table.len() / METADATA_SECTION_SIZE;
    let mut opaque = vec![false; count];
    let entries = || (table.clone()).step_by(METADATA_SECTION_SIZE);
    if !entries().any(|s| matches!(u32_at(b, s + 16), Ok(2 | 3))) {
        return Ok(opaque);
    }
    let plain_header = &b[..metadata_info];
    let elf = span(plain_header, u64_at(b, 48)?, ELF64_HEADER_SIZE as u64)?;
    let e = &b[elf.clone()];
    let short = |at| u16::from_be_bytes([e[at], e[at + 1]]) as usize;
    if elf.start < 104
        || &e[..7] != b"\x7fELF\x02\x02\x01"
        || short(16) != 2 // ET_EXEC
        || short(18) != 21 // EM_PPC64
        || u32_at(e, 20)? != 1
        || short(52) != ELF64_HEADER_SIZE
        || short(54) != ELF64_PROGRAM_SIZE
        || short(58) != ELF64_SECTION_SIZE
    {
        return Ok(opaque);
    }
    let phnum = short(56);
    let shnum = short(60);
    if phnum == 0 || phnum == 0xffff || shnum == 0 || short(62) >= shnum {
        return Ok(opaque);
    }
    let elf_len = u64_at(b, 24)?;
    let file_range = |offset: u64, size: u64| -> Result<Range<u64>, Error> {
        crate::range(offset, size, elf_len)?;
        Ok(offset..offset + size)
    };
    let elf_ph = file_range(u64_at(e, 32)?, (phnum * ELF64_PROGRAM_SIZE) as u64)?;
    let elf_sh = file_range(u64_at(e, 40)?, (shnum * ELF64_SECTION_SIZE) as u64)?;
    if elf_ph.start < ELF64_HEADER_SIZE as u64 || elf_sh.start < elf_ph.end {
        return Ok(opaque);
    }
    let ph = span(plain_header, u64_at(b, 56)?, elf_ph.end - elf_ph.start)?;
    if ph.start < elf.end {
        return Ok(opaque);
    }
    let sh = span(b, u64_at(b, 64)?, elf_sh.end - elf_sh.start)?;
    let mut storage = Vec::with_capacity(count);
    let mut section_table = None;
    let mut has_runtime = false;
    let mut mappings = vec![0u32; shnum];
    for s in entries() {
        check_cancel(cancel)?;
        let r = span(b, u64_at(b, s)?, u64_at(b, s + 8)?)?;
        if r.start < header_len {
            return Ok(opaque);
        }
        if !r.is_empty() {
            storage.push(r.clone());
        }
        has_runtime |= u32_at(b, s + 16)? == 2;
        if r == sh {
            if section_table.is_some()
                || u32_at(b, s + 16)? != 1
                || u32_at(b, s + 24)? != 2
                || u64::from(u32_at(b, s + 28)?) + 6 > key_count as u64
                || u32_at(b, s + 32)? != 1
                || u32_at(b, s + 44)? != 1
            {
                return Ok(opaque);
            }
            section_table = Some(s);
        }
        if u32_at(b, s + 16)? == 3 {
            let index = u32_at(b, s + 20)? as usize;
            if let Some(n) = mappings.get_mut(index) {
                *n += 1;
            }
        }
    }
    storage.sort_unstable_by_key(|r| r.start);
    if storage.windows(2).any(|w| w[0].end > w[1].start) {
        return Ok(opaque);
    }
    let Some(section_table) = section_table else {
        return Ok(opaque);
    };
    // Sorted ranges and prefix maxima keep classification O(n log n), even for overlapping PHDRs.
    let mut programs = Vec::with_capacity(phnum);
    for p in (ph.start..ph.end).step_by(ELF64_PROGRAM_SIZE) {
        check_cancel(cancel)?;
        let r = file_range(u64_at(b, p + 8)?, u64_at(b, p + 32)?)?;
        if !r.is_empty() {
            programs.push(r);
        }
    }
    programs.sort_unstable_by_key(|r| r.start);
    let mut end = 0;
    for r in &mut programs {
        end = end.max(r.end);
        r.end = end;
    }
    let before = programs.partition_point(|p| p.start < elf_sh.end);
    if elf_sh.start < ELF64_HEADER_SIZE as u64
        || (elf_sh.start < elf_ph.end && elf_ph.start < elf_sh.end)
        || (before > 0 && programs[before - 1].end > elf_sh.start)
    {
        return Ok(opaque);
    }
    let segments = span(
        plain_header,
        u64_at(b, 72)?,
        (phnum * SELF_SEGMENT_SIZE) as u64,
    )?;
    if segments.start < ph.end {
        return Ok(opaque);
    }
    for s in (segments.start..segments.end).step_by(SELF_SEGMENT_SIZE) {
        check_cancel(cancel)?;
        let r = span(b, u64_at(b, s)?, u64_at(b, s + 8)?)?;
        if !r.is_empty() && r.start < sh.end && sh.start < r.end {
            return Ok(opaque);
        }
    }
    let table_authenticated = verify_hash(section_table, &b[sh.clone()])?;
    // The table's role needs no trusted contents, but decoded runtime must remain strict.
    if has_runtime {
        opaque[(section_table - table.start) / METADATA_SECTION_SIZE] = true;
    }
    // Only authenticated section headers may exempt auxiliary bytes from hashing.
    if !table_authenticated {
        return Ok(opaque);
    }
    for (i, s) in entries().enumerate() {
        check_cancel(cancel)?;
        if u32_at(b, s + 16)? != 3
            || u32_at(b, s + 24)? != 2
            || u64::from(u32_at(b, s + 28)?) + 6 > key_count as u64
            || u32_at(b, s + 32)? != 1
            || u32_at(b, s + 44)? != 1
        {
            continue;
        }
        let index = u32_at(b, s + 20)? as usize;
        if index == 0 || mappings.get(index) != Some(&1) {
            continue;
        }
        let h = sh.start + index * ELF64_SECTION_SIZE;
        let size = u64_at(b, h + 32)?;
        if u32_at(b, h + 4)? != 1 // SHT_PROGBITS
            || u64_at(b, h + 8)? != 0 // No allocation, execution, TLS or unknown flags.
            || u64_at(b, h + 16)? != 0
            || size == 0
            || size != u64_at(b, s + 8)?
        {
            continue;
        }
        let r = file_range(u64_at(b, h + 24)?, size)?;
        let before = programs.partition_point(|p| p.start < r.end);
        if r.start < ELF64_HEADER_SIZE as u64
            || (r.start < elf_ph.end && elf_ph.start < r.end)
            || (r.start < elf_sh.end && elf_sh.start < r.end)
            || (before > 0 && programs[before - 1].end > r.start)
        {
            continue;
        }
        opaque[i] = true;
    }
    Ok(opaque)
}

pub(crate) fn convert(
    b: &mut [u8],
    rap: &Rap,
    cid: &[u8; 48],
    name: &str,
    cancel: &impl Fn() -> bool,
) -> Result<Vec<Vec<u8>>, Error> {
    let Some(npd) = npd_offset(b)? else {
        return Ok(vec![]);
    };
    let header_len = u64_at(b, 16)?;
    let cis = span(&b[..header_len as usize], u64_at(b, 88)?, u64_at(b, 96)?)?;
    let license = u32_at(b, npd + 8)?;
    if license == 3 {
        return Ok(vec![]);
    }
    if license != 2 {
        return Err(Error::Unsupported("SELF license type"));
    }
    if &b[npd + 16..npd + 64] != cid {
        return Err(Error::Unsupported(
            "SELF needs a different content ID / RAP",
        ));
    }
    let rev = u16::from_be_bytes(b[8..10].try_into().unwrap());
    let (erk, iv) = match rev {
        0x01 => (
            hex("f9edd0301f770fabba8863d9897f0fea6551b09431f61312654e28f43533ea6b"),
            hex("a551ccb4a42c37a734a2b4f9657d5540"),
        ),
        0x0a => (OUTPUT_ERK, OUTPUT_IV),
        0x19 => (
            hex("fbda75963fe690cff35b7aa7b408cf631744edef5f7931a04d58fd6a921ffdb3"),
            hex("f72c1d80ffda2e3bf085f4133e6d2805"),
        ),
        0x1c => (
            hex("8103ea9db790578219c4cedf0592b43064a7d98b601b6c7bc45108c4047aa80f"),
            hex("246f4b8328be6a2d394ede20479247c5"),
        ),
        _ => {
            return Err(Error::Unsupported(
                "NPDRM SELF key revision (supported: 01, 0A, 19, 1C)",
            ));
        }
    };
    let mi = u32_at(b, 12)? as usize + 32;
    let mir = span(&b[..header_len as usize], mi as u64, 64)?;
    if mi < cis.end {
        return Err(Error::Malformed("SELF metadata overlaps control records"));
    }
    cbc(
        &aes(&KLIC, rap.key, true),
        [0; 16],
        &mut b[mir.clone()],
        true,
    );
    cbc(&erk, iv, &mut b[mir.clone()], true);
    if b[mi + 16..mi + 32] != [0; 16] || b[mi + 48..mi + 64] != [0; 16] {
        return Err(Error::Malformed(
            "SELF metadata authentication failed; wrong RAP or damaged SELF",
        ));
    }
    let key = block(b, mi)?;
    let iv = block(b, mi + 32)?;
    let mh = mi + 64;
    ctr(&key, iv, &mut b[mh..header_len as usize]);
    span(&b[..header_len as usize], mh as u64, 32)?;
    let sig = u64_at(b, mh)?;
    let count = u32_at(b, mh + 12)? as usize;
    if count == 0 {
        return Err(Error::Malformed("local-license SELF has no sections"));
    }
    let keys = u32_at(b, mh + 16)? as usize;
    if count > 65536 || keys > 1_000_000 {
        return Err(Error::LimitExceeded("SELF section/key count"));
    }
    let table = span(
        &b[..header_len as usize],
        (mh + 32) as u64,
        count as u64 * 48,
    )?;
    let kr = span(
        &b[..header_len as usize],
        table.end as u64,
        keys as u64 * 16,
    )?;
    let opt = u32_at(b, mh + 20)? as usize;
    if sig != (kr.end + opt) as u64 {
        return Err(Error::Malformed("SELF signature offset"));
    }
    let signature = span(&b[..header_len as usize], sig, 48)?;
    let get_key = |index: usize, size: usize| -> Result<&[u8], Error> {
        let r = span(&b[kr.clone()], index as u64 * 16, size as u64)?;
        Ok(&b[kr.start + r.start..kr.start + r.end])
    };
    let verify_hash = |s: usize, payload: &[u8]| -> Result<bool, Error> {
        if u32_at(b, s + 24)? != 2 {
            return Err(Error::Unsupported("unhashed SELF section"));
        }
        let hi = u32_at(b, s + 28)? as usize;
        Ok(hmac(get_key(hi + 2, 64)?, payload) == get_key(hi, 20)?)
    };
    let opaque = opaque_sections(
        b,
        header_len as usize,
        mi,
        table.clone(),
        keys,
        verify_hash,
        cancel,
    )?;
    let mut decoded = Vec::new();
    let mut total = 0u64;
    for (i, is_opaque) in opaque.into_iter().enumerate() {
        check_cancel(cancel)?;
        let s = table.start + i * 48;
        let r = span(b, u64_at(b, s)?, u64_at(b, s + 8)?)?;
        if r.start < header_len as usize {
            return Err(Error::Malformed("SELF section overlaps header"));
        }
        if is_opaque {
            continue;
        }
        let mut payload = b[r].to_vec();
        match u32_at(b, s + 32)? {
            3 => ctr(
                get_key(u32_at(b, s + 36)? as usize, 16)?
                    .try_into()
                    .unwrap(),
                get_key(u32_at(b, s + 40)? as usize, 16)?
                    .try_into()
                    .unwrap(),
                &mut payload,
            ),
            1 => {}
            _ => return Err(Error::Unsupported("SELF section encryption")),
        }
        if !verify_hash(s, &payload)? {
            return Err(Error::Malformed("SELF section hash mismatch"));
        }
        match u32_at(b, s + 44)? {
            2 => {
                let mut out = Vec::new();
                flate2::read::ZlibDecoder::new(payload.as_slice())
                    .take(MAX_FILE + 1)
                    .read_to_end(&mut out)?;
                payload = out;
            }
            1 => {}
            _ => return Err(Error::Unsupported("SELF section compression")),
        }
        total += payload.len() as u64;
        if total > MAX_FILE {
            return Err(Error::LimitExceeded("decoded SELF sections"));
        }
        decoded.push(payload);
    }
    b[8..10].copy_from_slice(&0x0au16.to_be_bytes());
    put32(b, npd + 8, 3);
    let mut title = cid.to_vec();
    title.extend_from_slice(name.as_bytes());
    b[npd + 80..npd + 96].copy_from_slice(&cmac(&OMAC3, &title));
    let hash = cmac(&xor(OMAC2, FREE), &b[npd..npd + 96]);
    b[npd + 96..npd + 112].copy_from_slice(&hash);
    let signature_bytes = sign::sign(&b[..sig as usize]);
    b[signature].copy_from_slice(&signature_bytes);
    ctr(&key, iv, &mut b[mh..header_len as usize]);
    cbc(&OUTPUT_ERK, OUTPUT_IV, &mut b[mir.clone()], false);
    cbc(&aes(&KLIC, FREE, true), [0; 16], &mut b[mir], false);
    Ok(decoded)
}
