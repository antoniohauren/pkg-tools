use super::{BLOCK, BaseContainerLayout, DIGESTS, entry_range, invalid};
use crate::inner_image::check;
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;

/// SHA256 over final stored (encrypted) outer bytes, not plaintext HMAC inputs.
pub struct PfsDigests {
    pub first_block: [u8; 32],
    pub image: [u8; 32],
}

/// Header fields computed after stored-entry DIGESTS have been written.
pub struct BodyDigests {
    pub body: [u8; 32],
    pub digest_table: [u8; 32],
    pub sc_entries1: [u8; 32],
    pub sc_entries2: [u8; 32],
}

// Read explicitly rather than read_exact: cancellation also runs on short reads.
fn read_block(
    source: &mut impl Read,
    mut bytes: &mut [u8],
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        check(cancelled)?;
        match source.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    check(cancelled)
}

fn hash_ranges(
    source: &mut (impl Read + Seek),
    ranges: &[Range<u64>],
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = [0; BLOCK as usize];
    for range in ranges {
        check(cancelled)?;
        source.seek(SeekFrom::Start(range.start))?;
        let mut left = range.end - range.start;
        while left != 0 {
            let count = left.min(BLOCK) as usize;
            read_block(source, &mut buffer[..count], cancelled)?;
            hash.update(&buffer[..count]);
            left -= count as u64;
        }
    }
    Ok(hash.finalize().into())
}

impl BaseContainerLayout {
    fn check_length(
        &self,
        source: &mut impl Seek,
        cancelled: &mut impl FnMut() -> bool,
    ) -> io::Result<()> {
        check(cancelled)?;
        if source.seek(SeekFrom::End(0))? != self.package_size() {
            return Err(invalid("scratch length differs from final package layout"));
        }
        Ok(())
    }

    /// Stream package-relative PlayGo SHA slots to a separate output, including
    /// zero pre-PFS slots. Output starts at its current position; no image-sized
    /// allocation. Source must be final, stable package-length scratch; output
    /// must not alias source. On any error discard partial output. No publication.
    pub fn write_playgo_sha(
        &self,
        source: &mut (impl Read + Seek),
        output: &mut impl Write,
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<PfsDigests> {
        self.check_length(source, &mut cancelled)?;
        let pfs = self.pfs_range();
        for _ in 0..pfs.start / BLOCK {
            check(&mut cancelled)?;
            output.write_all(&[0; 4])?;
        }
        source.seek(SeekFrom::Start(pfs.start))?;
        let mut buffer = [0; BLOCK as usize];
        let mut full = Sha256::new();
        let mut first_block = [0; 32];
        for offset in (pfs.start..pfs.end).step_by(BLOCK as usize) {
            read_block(source, &mut buffer, &mut cancelled)?;
            full.update(buffer);
            let digest = Sha256::digest(buffer);
            if offset == pfs.start {
                first_block.copy_from_slice(&digest);
            }
            check(&mut cancelled)?;
            output.write_all(&digest[..4])?;
        }
        check(&mut cancelled)?;
        Ok(PfsDigests {
            first_block,
            image: full.finalize().into(),
        })
    }

    /// Generate the small ID-indexed DIGESTS record, self slot zero. All source
    /// records must already contain final stored bytes (including encrypted ones).
    /// Caller writes returned bytes at planned 0x1 before `body_digests`.
    pub fn entry_digests(
        &self,
        source: &mut (impl Read + Seek),
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<Vec<u8>> {
        self.check_length(source, &mut cancelled)?;
        let mut result = vec![0; self.record(DIGESTS).size as usize];
        let base = u64::from(self.record(DIGESTS).offset);
        for (input, output) in self.entry_digest_ranges() {
            let digest = hash_ranges(source, &[input], &mut cancelled)?;
            let start = (output.start - base) as usize;
            result[start..start + 32].copy_from_slice(&digest);
        }
        Ok(result)
    }

    /// Body includes padding; SC inputs concatenate declared lengths, not gaps.
    /// Caller must first write final DIGESTS, table, names and all other records.
    pub fn body_digests(
        &self,
        source: &mut (impl Read + Seek),
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<BodyDigests> {
        self.check_length(source, &mut cancelled)?;
        let [first, second] = self.sc_digest_ranges();
        Ok(BodyDigests {
            body: hash_ranges(source, &[self.body_range()], &mut cancelled)?,
            digest_table: hash_ranges(
                source,
                &[entry_range(self.record(DIGESTS))],
                &mut cancelled,
            )?,
            sc_entries1: hash_ranges(source, &first, &mut cancelled)?,
            sc_entries2: hash_ranges(source, &second, &mut cancelled)?,
        })
    }
}

/// Final header SHA256 at 0xfe0; call after all header fields are finalized.
pub fn header_digest(header: &[u8; 0x1000]) -> [u8; 32] {
    Sha256::digest(&header[..0xfe0]).into()
}

/// Fake-signature *input*, not a signature. Header must already contain its hash.
pub fn signature_digest(header: &[u8; 0x1000]) -> io::Result<[u8; 32]> {
    if header[0xfe0..] != header_digest(header) {
        return Err(invalid("final header digest missing or stale"));
    }
    Ok(Sha256::digest(header).into())
}

/// Type-0x100 general-digest record for GD/PS4 only. Final SFO bytes are hashed
/// as supplied, never reserialized/edited (including PUBTOOLVER). Header must
/// already hold final content identity/layout and stored-PFS digests. Does not
/// authenticate those caller-supplied values or generate unknown digest types.
pub fn general_digests(header: &[u8; 0x1000], final_sfo: &[u8]) -> io::Result<[u8; 0x180]> {
    if &header[..4] != b"\x7fCNT"
        || header[0x70..0x74] != 15u32.to_be_bytes()
        || header[0x74..0x78] != 26u32.to_be_bytes()
    {
        return Err(invalid("general digests require PS4 GD header"));
    }
    let sfo = psf::parse(final_sfo).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if sfo.version != 0x101 {
        return Err(invalid("general digests require SFO 1.1"));
    }
    let text = |key: &[u8]| -> io::Result<&[u8]> {
        match sfo.get(key).map(|e| &e.value) {
            Some(psf::Value::Text(value)) if value.is_ascii() => Ok(value),
            _ => Err(invalid(
                "missing or non-ASCII/text general-digest SFO field",
            )),
        }
    };
    let content_id = text(b"CONTENT_ID")?;
    if content_id.len() != 36
        || !crate::gp4::valid_content_id(
            std::str::from_utf8(content_id).map_err(|_| invalid("content ID"))?,
        )
        || header[0x40..0x64] != *content_id
        || header[0x64..0x70] != [0; 12]
        || text(b"CATEGORY")? != b"gd"
    {
        return Err(invalid(
            "SFO/header identity mismatch or unsupported category",
        ));
    }
    let mut major = Sha256::new();
    for key in [
        b"ATTRIBUTE".as_slice(),
        b"ATTRIBUTE2",
        b"CATEGORY",
        b"FORMAT",
        b"PUBTOOLVER",
    ] {
        if key == b"ATTRIBUTE2" && sfo.get(key).is_none() {
            continue;
        }
        major.update(key);
        if matches!(key, b"CATEGORY" | b"FORMAT") {
            major.update(text(key)?);
        } else {
            match sfo.get(key).map(|e| &e.value) {
                Some(psf::Value::Integer(value)) => {
                    major.update(format!("0x{value:08x}").as_bytes())
                }
                _ => return Err(invalid("missing or non-integer general-digest SFO field")),
            }
        }
    }
    let major: [u8; 32] = major.finalize().into();
    let mut content = Sha256::new();
    content.update(&header[0x40..0x78]);
    content.update(&header[0x440..0x460]);
    content.update(major);
    let mut general_header = Sha256::new();
    general_header.update(&header[..0x40]);
    general_header.update(&header[0x400..0x480]);
    let mut result = [0; 0x180];
    result[..4].copy_from_slice(&[0xd2, 0x56, 1, 0]);
    // Content, Game, Header, MajorParam and Param present; System stays unset.
    result[28..32].copy_from_slice(&0x6eu32.to_be_bytes());
    result[32..64].copy_from_slice(&content.finalize());
    result[64..96].copy_from_slice(&header[0x440..0x460]);
    result[96..128].copy_from_slice(&general_header.finalize());
    result[160..192].copy_from_slice(&major);
    result[192..224].copy_from_slice(&Sha256::digest(final_sfo));
    Ok(result)
}
