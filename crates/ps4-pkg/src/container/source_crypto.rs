//! Preserve source-bound crypto records; never generate or alter a license.
use super::{BaseContainerLayout, encrypt_metadata, invalid};
use crate::{Package, crypto};
use rsa::Pkcs1v15Encrypt;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Read, Seek, SeekFrom},
};

const ENTRY_KEYS: u32 = 0x10;
const IMAGE_KEY: u32 = 0x20;
const LICENSE_DAT: u32 = 0x400;
const LICENSE_INFO: u32 = 0x401;
const KEY_BYTES: usize = 0x800;

/// Validated candidate passcode and unchanged source identity. Contains sensitive
/// material deliberately excluded from Debug. No license signature authentication
/// is claimed: stored-byte digests and the supported license fields are checked,
/// while the original RIF secret and signature remain opaque and unchanged.
/// Caller must preserve SFO/keystone/application identity and reject unsupported
/// application semantics; this helper does not establish console compatibility.
pub struct SourceCrypto {
    content_id: String,
    passcode: String,
    entry_keys: [u8; KEY_BYTES],
    image_key: [u8; 32],
    source_image_key: [u8; 32],
    plaintext: BTreeMap<u32, Vec<u8>>,
}

impl SourceCrypto {
    /// Read the legacy or supported new-crypt GD base profile. Supply a candidate (normally
    /// 32 ASCII zeros); a mismatch stops before any metadata decryption. No search,
    /// passcode recovery, substituted keys, license generation or source writes.
    pub fn from_package<R: Read + Seek>(
        package: &mut Package<R>,
        passcode: &str,
    ) -> io::Result<Self> {
        let h = package.header();
        let newcrypt = h.flags == 0x4000_0001 && h.pfs_flags == 0xa000_0000_0000_03cc;
        let legacy = h.flags == 1 && h.pfs_flags == 0x8000_0000_0000_03cc;
        if (!legacy && !newcrypt)
            || h.drm_type != 0xf
            || h.content_type != 0x1a
            || h.content_flags != 0x0a00_0000
            || h.content_id[36..] != [0; 12]
        {
            return Err(invalid(
                "source crypto requires supported legacy GD base profile",
            ));
        }
        let content_id = std::str::from_utf8(&h.content_id[..36])
            .map_err(|_| invalid("invalid source content ID"))?
            .to_owned();
        // Reuse the public validation for both identity and candidate syntax.
        let image_key = crate::outer_image::legacy_image_key(&content_id, passcode)?;
        if package.entries().iter().any(|e| {
            !matches!(
                e.id,
                1 | 0x10 | 0x20 | 0x80 | 0x100 | 0x200 | 0x400..=0x403 | 0x409 | 0x1000
                    ..=0x1006 | 0x100d | 0x1200 | 0x1220 | 0x1240 | 0x1260 | 0x1280 | 0x12a0 | 0x12c0 | 0x1400
            )
        }) {
            return Err(invalid(
                "unsupported source records require preservation semantics",
            ));
        }
        if package
            .entries()
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(invalid("source crypto requires ID-sorted entry table"));
        }
        let mut resource_total = 0u64;
        for entry in package
            .entries()
            .iter()
            .filter(|e| super::record_name(e.id).is_some())
        {
            if (entry.flags1, entry.flags2) != super::record_flags(entry.id)
                || entry.size == 0
                || entry.size > super::MAX_RESOURCE_SIZE
            {
                return Err(invalid("unsupported source resource flags or length"));
            }
            resource_total += u64::from(entry.size);
        }
        if resource_total > super::MAX_RESOURCE_TOTAL {
            return Err(invalid("source resources exceed 64 MiB"));
        }
        let (keys_record, keys) = read_record(package, ENTRY_KEYS, KEY_BYTES)?;
        if word(&keys_record, 8) != 0x6000_0000 || word(&keys_record, 12) != 0 {
            return Err(invalid("unsupported source ENTRY_KEYS flags"));
        }
        let entry_keys: [u8; KEY_BYTES] = keys
            .try_into()
            .map_err(|_| invalid("invalid source ENTRY_KEYS length"))?;
        verify_passcode(&entry_keys, &content_id, passcode)?;
        let dk3 = crypto::recover_dk3(&entry_keys)
            .map_err(|_| invalid("source wrapped D[3] verification failed"))?;
        if dk3 != derived(&content_id, passcode, 3)? {
            return Err(invalid("source wrapped D[3] disagrees with candidate"));
        }

        let mut plaintext = BTreeMap::new();
        let mut stored = BTreeMap::from([(ENTRY_KEYS, entry_keys.to_vec())]);
        let has_np = package.entries().iter().any(|e| e.id == 0x402);
        if has_np != package.entries().iter().any(|e| e.id == 0x403) {
            return Err(invalid(
                "source NP title and binding records must occur together",
            ));
        }
        let mut encrypted = vec![
            (IMAGE_KEY, 0x100, 3),
            (LICENSE_DAT, 0x400, 3),
            (LICENSE_INFO, 0x200, 2),
        ];
        if has_np {
            encrypted.extend([(0x402, 0xa0, 3), (0x403, 0x214, 3)]);
        }
        for (id, size, index) in encrypted {
            let (record, ciphertext) = read_record(package, id, size)?;
            let expected_flags = if id == IMAGE_KEY {
                0xe000_0000
            } else {
                0x8000_0000
            };
            if word(&record, 8) != expected_flags || word(&record, 12) != index << 12 {
                return Err(invalid("unsupported source crypto record flags"));
            }
            let material: [u8; 32] = Sha256::digest(
                [record.as_slice(), &derived(&content_id, passcode, index)?].concat(),
            )
            .into();
            let mut plain = ciphertext.clone();
            super::encryption::decrypt_metadata(&mut plain, &material)?;
            if id == 0x403 {
                if plain[size..].iter().any(|&b| b != 0) {
                    return Err(invalid("unsupported NP binding encrypted padding"));
                }
                plain.truncate(size);
            }
            plaintext.insert(id, plain);
            stored.insert(id, ciphertext);
        }
        verify_stored_digests(package, &stored)?;
        let recovered = crypto::rsa_key(true)
            .decrypt(Pkcs1v15Encrypt, &plaintext[&IMAGE_KEY])
            .map_err(|_| invalid("source fake IMAGE_KEY wrapping is invalid"))?;
        let source_image_key: [u8; 32] = recovered
            .try_into()
            .map_err(|_| invalid("invalid source IMAGE_KEY length"))?;
        if legacy && source_image_key != image_key {
            return Err(invalid("source IMAGE_KEY is not legacy candidate D[1]"));
        }
        if newcrypt {
            use rsa::traits::PublicKeyParts;
            // Destination deliberately uses the legacy D[1]/zero-seed profile.
            plaintext.insert(
                IMAGE_KEY,
                super::public_rsa_wrap(
                    &crypto::rsa_key(true).n().to_bytes_be(),
                    &[1, 0, 1],
                    &image_key,
                )?
                .to_vec(),
            );
        }
        validate_licenses(
            &content_id,
            &plaintext[&LICENSE_DAT],
            &plaintext[&LICENSE_INFO],
        )?;
        Ok(Self {
            content_id,
            passcode: passcode.to_owned(),
            entry_keys,
            image_key,
            source_image_key,
            plaintext,
        })
    }

    pub fn content_id(&self) -> &str {
        &self.content_id
    }

    /// Ready legacy image key for the outer-image writer, not for display/logging.
    pub fn image_key(&self) -> &[u8; 32] {
        &self.image_key
    }

    /// Ready source outer key (new-crypt inputs need not equal destination D[1]).
    pub fn source_image_key(&self) -> &[u8; 32] {
        &self.source_image_key
    }

    /// Original blob, including wrapped passcode and all seven wrapped keys.
    pub fn entry_keys(&self) -> &[u8; KEY_BYTES] {
        &self.entry_keys
    }

    /// Return ENTRY_KEYS and re-encrypted IMAGE_KEY, licenses and original NP for
    /// the exact final layout. No identity argument: changing content ID is not
    /// supported. Whole license plaintext (including secret/signature) is retained.
    /// NP binding retains declared size 0x214 but returns 0x220 stored/hash bytes.
    pub fn encrypt_for_layout(
        &self,
        layout: &BaseContainerLayout,
    ) -> io::Result<BTreeMap<u32, Vec<u8>>> {
        let mut records = BTreeMap::from([(ENTRY_KEYS, self.entry_keys.to_vec())]);
        for record in layout.entry_table().as_chunks::<32>().0 {
            let id = word(record, 0);
            if matches!(id, 0x20 | 0x400..=0x403) && !self.plaintext.contains_key(&id) {
                return Err(invalid("final layout invents source crypto record"));
            }
            if let Some(plain) = self.plaintext.get(&id) {
                records.insert(
                    id,
                    encrypt_metadata(record, &self.content_id, &self.passcode, plain)?,
                );
            }
        }
        if records.len() != self.plaintext.len() + 1 {
            return Err(invalid("final layout lacks source crypto records"));
        }
        Ok(records)
    }
}

fn word(record: &[u8; 32], offset: usize) -> u32 {
    u32::from_be_bytes([
        record[offset],
        record[offset + 1],
        record[offset + 2],
        record[offset + 3],
    ])
}

fn derived(content_id: &str, passcode: &str, index: u32) -> io::Result<[u8; 32]> {
    Ok(crypto::derived_key(
        content_id
            .as_bytes()
            .try_into()
            .map_err(|_| invalid("invalid content ID length"))?,
        passcode
            .as_bytes()
            .try_into()
            .map_err(|_| invalid("invalid passcode length"))?,
        index,
    ))
}

fn verify_passcode(keys: &[u8; KEY_BYTES], content_id: &str, passcode: &str) -> io::Result<()> {
    crate::outer_image::legacy_image_key(content_id, passcode)?;
    let mut padded_id = [0; 48];
    padded_id[..36].copy_from_slice(content_id.as_bytes());
    if keys[..32] != Sha256::digest(padded_id)[..] {
        return Err(invalid("source ENTRY_KEYS content identity mismatch"));
    }
    // Pinned L Entry.cs:215-243/Pkg.cs:94-120: all seven digests are
    // SHA256(D[i]) XOR D[i], even slot zero (whose RSA payload is passcode).
    let mut difference = 0;
    for index in 0..7 {
        let key = derived(content_id, passcode, index)?;
        for (byte, (&hash, &value)) in Sha256::digest(key).iter().zip(&key).enumerate() {
            difference |= hash ^ value ^ keys[32 + index as usize * 32 + byte];
        }
    }
    if difference != 0 {
        return Err(invalid(
            "candidate passcode does not match source ENTRY_KEYS",
        ));
    }
    Ok(())
}

fn read_record<R: Read + Seek>(
    package: &mut Package<R>,
    id: u32,
    size: usize,
) -> io::Result<([u8; 32], Vec<u8>)> {
    let index = package
        .entries()
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| invalid("required source crypto record missing"))?;
    let entry = package.entries()[index].clone();
    if entry.size as usize != size || !entry.offset.is_multiple_of(16) {
        return Err(invalid(
            "unsupported source crypto record size or alignment",
        ));
    }
    let offset = entry.offset;
    let mut record = [0; 32];
    package.reader.seek(SeekFrom::Start(
        u64::from(package.header.entry_table_offset) + index as u64 * 32,
    ))?;
    package.reader.read_exact(&mut record)?;
    if record[24..] != [0; 8]
        || word(&record, 0) != id
        || word(&record, 16) != offset
        || word(&record, 20) as usize != size
        || word(&record, 4) != entry.name_offset
        || word(&record, 8) != entry.flags1
        || word(&record, 12) != entry.flags2
    {
        return Err(invalid(
            "source crypto table changed or contains reserved data",
        ));
    }
    // Source-confirmed NP binding declares 0x214 but encrypts/hashes 0x220 bytes.
    let stored_size = if id == 0x403 {
        size.next_multiple_of(16)
    } else {
        size
    };
    let stored_end = u64::from(offset) + stored_size as u64;
    if package.entries().iter().any(|e| {
        e.id != id && u64::from(e.offset) >= u64::from(offset) && u64::from(e.offset) < stored_end
    }) {
        return Err(invalid("source encrypted storage overlaps another record"));
    }
    if u64::from(offset) + stored_size as u64
        > package.header().body_offset + package.header().body_size
    {
        return Err(invalid("source crypto storage exceeds container body"));
    }
    let mut bytes = vec![0; stored_size];
    package.reader.seek(SeekFrom::Start(u64::from(offset)))?;
    package.reader.read_exact(&mut bytes)?;
    Ok((record, bytes))
}

fn verify_stored_digests<R: Read + Seek>(
    package: &mut Package<R>,
    stored: &BTreeMap<u32, Vec<u8>>,
) -> io::Result<()> {
    let size = package.entries().len() * 32;
    let (record, digests) = read_record(package, 1, size)?;
    if word(&record, 8) != 0x4000_0000 || word(&record, 12) != 0 || digests[..32] != [0; 32] {
        return Err(invalid("unsupported source DIGESTS record"));
    }
    for (&id, data) in stored {
        let index = package
            .entries()
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| invalid("source digest record missing"))?;
        if digests[index * 32..(index + 1) * 32] != Sha256::digest(data)[..] {
            return Err(invalid("source crypto stored-byte digest mismatch"));
        }
    }
    Ok(())
}

fn validate_licenses(content_id: &str, dat: &[u8], info: &[u8]) -> io::Result<()> {
    // Pinned L Rif/LicenseDat.cs:139-166 and LicenseInfo.cs:31-39: neither
    // serialized record contains table offsets, image hashes or passcode fields.
    // Preserving identity/type and every plaintext byte preserves its binding.
    if dat.len() != 0x400
        || info.len() != 0x200
        || &dat[..4] != b"RIF\0"
        || dat[4..8] != [0, 1, 0xff, 0xff]
        || &dat[0x20..0x44] != content_id.as_bytes()
        || dat[0x44..0x50] != [0; 12]
        || dat[0x50..0x58] != [2, 0, 0, 0xf, 0, 0x1a, 0, 3]
        || dat[8..16] != [0; 8]
        || dat[0x300..].iter().all(|&b| b == 0)
        || &info[..36] != content_id.as_bytes()
        || info[36..64] != [0; 28]
        || info[64..80] != [0, 0, 0, 0, 0, 0, 0, 0x1a, 0, 0, 0, 0, 0, 0, 0, 1]
        || info[80..].iter().any(|&b| b != 0)
    {
        return Err(invalid(
            "unsupported source debug GD license identity or structure",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{RecordSize, public_rsa_wrap};
    use super::*;
    use rsa::traits::PublicKeyParts;
    use std::io::Cursor;

    const ID: &str = "ZZ0000-CUSA00000_00-SYNTHETIC0000000";
    const PASS: &str = "00000000000000000000000000000000";

    #[test]
    #[ignore = "requires a private new-crypt base fixture; reports no material"]
    fn private_newcrypt_resource_preparation() {
        let path = std::env::var_os("PKG_TOOLS_RESOURCE_SOURCE").expect("fixture path");
        let mut package = Package::open(std::fs::File::open(path).unwrap()).unwrap();
        let source = SourceCrypto::from_package(&mut package, PASS).unwrap();
        assert!(source.source_image_key() != source.image_key());
        assert_eq!(source.plaintext[&0x402].len(), 0xa0);
        assert_eq!(source.plaintext[&0x403].len(), 0x214);
    }

    fn licenses() -> (Vec<u8>, Vec<u8>) {
        let mut dat = vec![0; 0x400];
        dat[..8].copy_from_slice(b"RIF\0\0\x01\xff\xff");
        dat[0x20..0x44].copy_from_slice(ID.as_bytes());
        dat[0x50..0x58].copy_from_slice(&[2, 0, 0, 15, 0, 26, 0, 3]);
        // Opaque synthetic payload, deliberately not a real signed/debug license.
        for (i, byte) in dat[0x250..].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let mut info = vec![0; 0x200];
        info[..36].copy_from_slice(ID.as_bytes());
        info[71] = 26;
        info[79] = 1;
        (dat, info)
    }

    fn plan(art: bool) -> BaseContainerLayout {
        let mut sizes = vec![
            RecordSize {
                id: 0x1000,
                size: 32,
            },
            RecordSize {
                id: 0x1003,
                size: 32,
            },
        ];
        if art {
            sizes.push(RecordSize {
                id: 0x1200,
                size: 32,
            });
        }
        BaseContainerLayout::plan(0x10000, &sizes).unwrap()
    }

    fn fixture() -> (Vec<u8>, BaseContainerLayout) {
        fixture_profile(false)
    }

    fn fixture_profile(np: bool) -> (Vec<u8>, BaseContainerLayout) {
        let layout = if np {
            BaseContainerLayout::plan(
                0x10000,
                &[
                    RecordSize {
                        id: 0x1000,
                        size: 32,
                    },
                    RecordSize {
                        id: 0x1003,
                        size: 32,
                    },
                    RecordSize {
                        id: 0x402,
                        size: 0xa0,
                    },
                    RecordSize {
                        id: 0x403,
                        size: 0x214,
                    },
                    RecordSize {
                        id: 0x1400,
                        size: 99,
                    },
                ],
            )
            .unwrap()
        } else {
            plan(false)
        };
        let mut bytes = vec![0; layout.package_size() as usize];
        bytes[..4].copy_from_slice(b"\x7fCNT");
        for (offset, value) in [
            (4, 1u32),
            (0x10, layout.records().len() as u32),
            (
                0x18,
                layout
                    .records()
                    .iter()
                    .find(|e| e.id == 0x100)
                    .unwrap()
                    .offset,
            ),
            (0x70, 15),
            (0x74, 26),
            (0x78, 0x0a00_0000),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [
            (0x20, layout.body_range().start),
            (0x28, layout.body_range().end - layout.body_range().start),
            (0x408, 0x8000_0000_0000_03cc),
            (0x410, layout.pfs_range().start),
            (0x418, layout.pfs_range().end - layout.pfs_range().start),
            (0x430, layout.package_size()),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[0x40..0x64].copy_from_slice(ID.as_bytes());
        let table = layout.entry_table();
        let mut keys = [0u8; KEY_BYTES];
        let mut padded_id = [0; 48];
        padded_id[..36].copy_from_slice(ID.as_bytes());
        keys[..32].copy_from_slice(&Sha256::digest(padded_id));
        for index in 0..7 {
            let key = derived(ID, PASS, index).unwrap();
            for (i, (&hash, &value)) in Sha256::digest(key).iter().zip(&key).enumerate() {
                keys[32 + index as usize * 32 + i] = hash ^ value;
            }
        }
        let modulus = crypto::rsa_key(false).n().to_bytes_be();
        keys[256 + 3 * 256..256 + 4 * 256].copy_from_slice(
            &public_rsa_wrap(&modulus, &[1, 0, 1], &derived(ID, PASS, 3).unwrap()).unwrap(),
        );
        let image = public_rsa_wrap(
            &crypto::rsa_key(true).n().to_bytes_be(),
            &[1, 0, 1],
            &derived(ID, PASS, 1).unwrap(),
        )
        .unwrap();
        let (dat, info) = licenses();
        let mut plain = BTreeMap::from([
            (IMAGE_KEY, image.to_vec()),
            (LICENSE_DAT, dat),
            (LICENSE_INFO, info),
        ]);
        if np {
            plain.insert(0x402, (0..0xa0).map(|i| (i % 251) as u8).collect());
            plain.insert(0x403, (0..0x214).map(|i| (i % 251) as u8).collect());
        }
        for record in table.as_chunks::<32>().0 {
            let id = word(record, 0);
            let start = word(record, 16) as usize;
            let data = match id {
                ENTRY_KEYS => keys.to_vec(),
                0x100 => table.clone(),
                IMAGE_KEY | LICENSE_DAT | LICENSE_INFO | 0x402 | 0x403 => {
                    encrypt_metadata(record, ID, PASS, &plain[&id]).unwrap()
                }
                _ => vec![0; word(record, 20) as usize],
            };
            bytes[start..start + data.len()].copy_from_slice(&data);
        }
        let digests = layout.records().iter().find(|e| e.id == 1).unwrap().offset as usize;
        for (index, record) in table.as_chunks::<32>().0.iter().enumerate().skip(1) {
            let start = word(record, 16) as usize;
            let size = word(record, 20) as usize;
            let end = start
                + if word(record, 0) == 0x403 {
                    size.next_multiple_of(16)
                } else {
                    size
                };
            let hash = Sha256::digest(&bytes[start..end]);
            bytes[digests + index * 32..digests + (index + 1) * 32].copy_from_slice(&hash);
        }
        (bytes, layout)
    }

    #[test]
    fn np_plaintext_survives_relocation_without_changing_length_or_role() {
        let (bytes, original) = fixture_profile(true);
        let mut package = Package::open(Cursor::new(bytes)).unwrap();
        let source = SourceCrypto::from_package(&mut package, PASS).unwrap();
        let sizes = [
            RecordSize {
                id: 0x1000,
                size: 32,
            },
            RecordSize {
                id: 0x1003,
                size: 32,
            },
            RecordSize {
                id: 0x402,
                size: 0xa0,
            },
            RecordSize {
                id: 0x403,
                size: 0x214,
            },
            RecordSize {
                id: 0x1400,
                size: 999,
            },
            RecordSize {
                id: 0x1200,
                size: 100,
            },
        ];
        let layout = BaseContainerLayout::plan(0x10000, &sizes).unwrap();
        let output = source.encrypt_for_layout(&layout).unwrap();
        for id in [0x402, 0x403] {
            let old = original.records().iter().find(|e| e.id == id).unwrap();
            let entry = layout.records().iter().find(|e| e.id == id).unwrap();
            assert_ne!(entry.offset, old.offset);
            let mut data = output[&id].clone();
            let key = derived(ID, PASS, u32::from(entry.key_index())).unwrap();
            super::super::encryption::decrypt_metadata(
                &mut data,
                &crypto::entry_material(entry, &key),
            )
            .unwrap();
            assert!(data[entry.size as usize..].iter().all(|&b| b == 0));
            data.truncate(entry.size as usize);
            assert_eq!(data, source.plaintext[&id]);
        }
        assert!(source.encrypt_for_layout(&plan(false)).is_err());
    }

    #[test]
    fn newcrypt_source_key_is_separate_from_destination_legacy_key() {
        let (mut bytes, layout) = fixture();
        bytes[4..8].copy_from_slice(&0x40000001u32.to_be_bytes());
        bytes[0x408..0x410].copy_from_slice(&0xa0000000000003ccu64.to_be_bytes());
        let table = layout.entry_table();
        let (index, row) = table
            .as_chunks::<32>()
            .0
            .iter()
            .enumerate()
            .find(|(_, r)| word(r, 0) == IMAGE_KEY)
            .unwrap();
        let source_key = [0x5a; 32];
        let wrapped = public_rsa_wrap(
            &crypto::rsa_key(true).n().to_bytes_be(),
            &[1, 0, 1],
            &source_key,
        )
        .unwrap();
        let stored = encrypt_metadata(row, ID, PASS, &wrapped).unwrap();
        let offset = word(row, 16) as usize;
        bytes[offset..offset + stored.len()].copy_from_slice(&stored);
        let digest_offset =
            layout.records().iter().find(|e| e.id == 1).unwrap().offset as usize + index * 32;
        bytes[digest_offset..digest_offset + 32].copy_from_slice(&Sha256::digest(stored));
        let mut package = Package::open(Cursor::new(bytes)).unwrap();
        let source = SourceCrypto::from_package(&mut package, PASS).unwrap();
        assert_eq!(source.source_image_key(), &source_key);
        assert_eq!(source.image_key(), &derived(ID, PASS, 1).unwrap());
        let destination = crypto::rsa_key(true)
            .decrypt(Pkcs1v15Encrypt, &source.plaintext[&IMAGE_KEY])
            .unwrap();
        assert_eq!(destination, source.image_key());
    }

    #[test]
    fn verifies_all_candidate_digests_and_identity_before_decryption() {
        let (bytes, _) = fixture();
        let mut package = Package::open(Cursor::new(bytes)).unwrap();
        let (_, keys) = read_record(&mut package, ENTRY_KEYS, KEY_BYTES).unwrap();
        let keys: [u8; KEY_BYTES] = keys.try_into().unwrap();
        verify_passcode(&keys, ID, PASS).unwrap();
        assert!(verify_passcode(&keys, ID, "11111111111111111111111111111111").is_err());
        for index in 0..7 {
            let mut bad = keys;
            bad[32 + index * 32] ^= 1;
            assert!(verify_passcode(&bad, ID, PASS).is_err());
        }
        assert!(verify_passcode(&keys, "ZZ0000-CUSA00001_00-SYNTHETIC0000000", PASS).is_err());
        assert!(verify_passcode(&keys, "short", PASS).is_err());
        let error = SourceCrypto::from_package(&mut package, "11111111111111111111111111111111")
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "candidate passcode does not match source ENTRY_KEYS"
        );
    }

    #[test]
    fn preserves_plaintext_and_original_wrapping_after_layout_changes() {
        let (bytes, original) = fixture();
        let mut package = Package::open(Cursor::new(bytes)).unwrap();
        let source = SourceCrypto::from_package(&mut package, PASS).unwrap();
        assert_eq!(source.content_id(), ID);
        assert_eq!(source.image_key(), &derived(ID, PASS, 1).unwrap());
        let final_layout = plan(true);
        let output = source.encrypt_for_layout(&final_layout).unwrap();
        assert_eq!(output[&ENTRY_KEYS], source.entry_keys());
        let original_table = original.entry_table();
        let final_table = final_layout.entry_table();
        for id in [IMAGE_KEY, LICENSE_DAT, LICENSE_INFO] {
            let old = original_table
                .as_chunks::<32>()
                .0
                .iter()
                .find(|r| word(r, 0) == id)
                .unwrap();
            let record = final_table
                .as_chunks::<32>()
                .0
                .iter()
                .find(|r| word(r, 0) == id)
                .unwrap();
            let index = if id == LICENSE_INFO { 2 } else { 3 };
            let key = derived(ID, PASS, index).unwrap();
            let material = Sha256::digest([record.as_slice(), &key].concat());
            let mut plain = output[&id].clone();
            crypto::cbc_decrypt(&mut plain, &material[16..], &material[..16]).unwrap();
            assert_eq!(plain, source.plaintext[&id]);
            if id != IMAGE_KEY {
                assert_ne!(word(old, 16), word(record, 16));
                assert_ne!(
                    output[&id],
                    encrypt_metadata(old, ID, PASS, &plain).unwrap()
                );
            }
        }
        let (dat, info) = licenses();
        assert_eq!(source.plaintext[&LICENSE_DAT], dat);
        assert_eq!(source.plaintext[&LICENSE_INFO], info);
    }

    #[test]
    fn rejects_corruption_truncation_unsupported_resources_and_records() {
        let (bytes, layout) = fixture();
        let table_offset = layout
            .records()
            .iter()
            .find(|e| e.id == 0x100)
            .unwrap()
            .offset as usize;
        let table = layout.entry_table();
        let image_index = table
            .as_chunks::<32>()
            .0
            .iter()
            .position(|r| word(r, 0) == IMAGE_KEY)
            .unwrap();
        for change in 0..6 {
            let mut bad = bytes.clone();
            match change {
                0 => {
                    bad[layout
                        .records()
                        .iter()
                        .find(|e| e.id == LICENSE_DAT)
                        .unwrap()
                        .offset as usize] ^= 1
                }
                1 => bad[table_offset + image_index * 32 + 31] = 1,
                2 => bad[table_offset + image_index * 32 + 14] = 0x20,
                3 => bad
                    [table_offset + image_index * 32 + 20..table_offset + image_index * 32 + 24]
                    .copy_from_slice(&240u32.to_be_bytes()),
                4 => bad[table_offset + image_index * 32..table_offset + image_index * 32 + 4]
                    .copy_from_slice(&0x1400u32.to_be_bytes()),
                _ => bad[0x78] ^= 1,
            }
            let mut package = Package::open(Cursor::new(bad)).unwrap();
            assert!(SourceCrypto::from_package(&mut package, PASS).is_err());
        }
        assert!(Package::open(Cursor::new(&bytes[..bytes.len() - 1])).is_err());
        let (dat, info) = licenses();
        assert!(validate_licenses(ID, &dat[..1023], &info).is_err());
        assert!(validate_licenses(ID, &dat, &info[..511]).is_err());
        let mut wrong_identity = dat.clone();
        wrong_identity[0x20] ^= 1;
        assert!(validate_licenses(ID, &wrong_identity, &info).is_err());
        let mut wrong_type = info;
        wrong_type[71] = 27;
        assert!(validate_licenses(ID, &dat, &wrong_type).is_err());
    }
}
