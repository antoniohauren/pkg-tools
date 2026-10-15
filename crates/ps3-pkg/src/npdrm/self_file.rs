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

/// Read the NPDRM content ID from a SELF header without decrypting its payload.
pub fn self_content_id(mut reader: impl Read) -> Result<[u8; 48], Error> {
    let mut prefix = [0; 104];
    reader.read_exact(&mut prefix)?;
    let length = u64_at(&prefix, 16)?;
    if !(104..=16 * 1024 * 1024).contains(&length) {
        return Err(Error::LimitExceeded("SELF header"));
    }
    let mut header = vec![0; length as usize];
    header[..104].copy_from_slice(&prefix);
    reader.read_exact(&mut header[104..])?;
    let offset = npd_offset(&header)?.ok_or(Error::Unsupported("SELF is not NPDRM"))?;
    Ok(header[offset + 16..offset + 64].try_into().unwrap())
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
                "NPDRM SELF key revision (supported: 0A, 19, 1C)",
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
    let mut decoded = Vec::new();
    let mut total = 0u64;
    for i in 0..count {
        check_cancel(cancel)?;
        let s = table.start + i * 48;
        let r = span(b, u64_at(b, s)?, u64_at(b, s + 8)?)?;
        if r.start < header_len as usize {
            return Err(Error::Malformed("SELF section overlaps header"));
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
        if u32_at(b, s + 24)? != 2 {
            return Err(Error::Unsupported("unhashed SELF section"));
        }
        let hi = u32_at(b, s + 28)? as usize;
        if hmac(get_key(hi + 2, 64)?, &payload) != get_key(hi, 20)? {
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
