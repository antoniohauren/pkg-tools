//! Checked layout for supported GD base container profiles.
//!
//! This is not a PKG writer or a readiness/installability check. Sizes reserve
//! required records; keyless PlayGo/integrity helpers operate on finalized bytes.
//! Caller-input metadata encryption and public RSA wrapping are separate helpers;
//! no licenses, authentic signatures or complete packages are generated.
//! See docs/fpkg-authoring-contract.md and fpkg-authoring-provenance.md.

use crate::Entry;
use std::{collections::BTreeMap, io, ops::Range};

mod encryption;
mod integrity;
mod playgo;
mod source_crypto;
pub use encryption::{encrypt_metadata, public_rsa_wrap};
pub use integrity::{BodyDigests, PfsDigests, general_digests, header_digest, signature_digest};
pub use playgo::DEFAULT_PLAYGO_MANIFEST;
pub use source_crypto::SourceCrypto;

const BODY_START: u64 = 0x2000;
const ENTRY_ALIGNMENT: u64 = 16;
const IMAGE_ALIGNMENT: u64 = 0x80000;
const BLOCK: u64 = 0x10000;
const RECORD_SIZE: u64 = 32;
const DIGESTS: u32 = 1;
const METAS: u32 = 0x100;
const NAMES: u32 = 0x200;
const PLAYGO_SHA: u32 = 0x1002;
const PLAYGO_DAT: u32 = 0x1001;
pub(super) const MAX_RESOURCE_SIZE: u32 = 16 * 1024 * 1024;
const MAX_RESOURCE_TOTAL: u64 = 64 * 1024 * 1024;
const SYSTEM_ORDER: [u32; 6] = [0x10, 0x20, 0x80, METAS, DIGESTS, NAMES];
const MAIN_ORDER: [u32; 5] = [0x10, 0x20, 0x80, METAS, DIGESTS];
const APPLICATION_ORDER: [u32; 7] = [0x1001, PLAYGO_SHA, 0x1003, 0x400, 0x401, 0x1000, 0x409];

/// Declared plaintext/stored length, excluding the following alignment padding.
/// Only final PARAM.SFO, PlayGo XML, supported named resources and paired NP
/// lengths may be supplied. Other generated slots cannot be supplied or omitted.
#[derive(Clone, Copy, Debug)]
pub struct RecordSize {
    pub id: u32,
    pub size: u64,
}

/// Immutable checked plan. Memory scales with the small supported record set,
/// not image size. Records are in physical order; METAS/digest slots use ID order.
pub struct BaseContainerLayout {
    records: Vec<Entry>,
    names: Vec<u8>,
    pfs_offset: u64,
    package_size: u64,
}

impl BaseContainerLayout {
    /// Plan one block-aligned outer image and the complete required record set.
    /// Required caller sizes: 0x1000 (final SFO), 0x1003 (PlayGo XML).
    /// Optional: the named base resources below and the paired NP records.
    /// Reserves the fixed 416-byte one-chunk PlayGo DAT and computed SHA length.
    /// NP lengths/flags match the supported base source profile; unknown/generated
    /// IDs, updates and arbitrary flags remain rejected. Resource caps: 16 MiB
    /// each, 64 MiB total. Trophy00 is opaque and must retain application identity.
    /// Length validation does not validate any supplied record's contents.
    pub fn plan(pfs_size: u64, supplied: &[RecordSize]) -> io::Result<Self> {
        if pfs_size == 0 || !pfs_size.is_multiple_of(BLOCK) {
            return Err(invalid("outer PFS size must be nonzero and 64-KiB aligned"));
        }
        let mut sizes = BTreeMap::new();
        for record in supplied {
            if (record_name(record.id).is_none() && !matches!(record.id, 0x402 | 0x403))
                || [PLAYGO_DAT, PLAYGO_SHA].contains(&record.id)
            {
                return Err(invalid("unsupported or generated container record ID"));
            }
            if record.size == 0 {
                return Err(invalid("supplied container records must be nonempty"));
            }
            let size = narrow(record.size)?;
            if size > MAX_RESOURCE_SIZE
                || (record.id == 0x402 && size != 0xa0)
                || (record.id == 0x403 && size != 0x214)
            {
                return Err(invalid("unsupported container resource length"));
            }
            if record.id == 0x1000 && size > crate::MAX_SFO_SIZE {
                return Err(invalid("PARAM.SFO exceeds 16 MiB"));
            }
            if sizes.insert(record.id, size).is_some() {
                return Err(invalid("duplicate container record ID"));
            }
        }
        if supplied.iter().map(|r| r.size).sum::<u64>() > MAX_RESOURCE_TOTAL {
            return Err(invalid("container resources exceed 64 MiB"));
        }
        if sizes.contains_key(&0x402) != sizes.contains_key(&0x403) {
            return Err(invalid("NP title and binding records must occur together"));
        }
        if [0x1000, 0x1003].iter().any(|id| !sizes.contains_key(id)) {
            return Err(invalid("final PARAM.SFO and PlayGo XML sizes are required"));
        }

        let mut order = SYSTEM_ORDER.to_vec();
        order.extend(APPLICATION_ORDER);
        order.extend(
            sizes
                .keys()
                .copied()
                .filter(|id| !APPLICATION_ORDER.contains(id)),
        );
        // The profile is much smaller, but both mirrored header counts must fit.
        let count = u16::try_from(order.len()).map_err(|_| invalid("container entry count"))?;
        let table_size = u32::from(count) * RECORD_SIZE as u32;
        for (id, size) in [
            (0x10, 0x800),
            (0x20, 0x100),
            (0x80, 0x180),
            (METAS, table_size),
            (DIGESTS, table_size),
            (0x400, 0x400),
            (0x401, 0x200),
            (0x409, 0x2000),
            (PLAYGO_DAT, 416),
        ] {
            sizes.insert(id, size);
        }

        let mut named: Vec<_> = order
            .iter()
            .filter_map(|&id| record_name(id).map(|name| (name, id)))
            .collect();
        named.sort_unstable();
        let mut names = vec![0];
        let mut name_offsets = BTreeMap::new();
        for (name, id) in named {
            name_offsets.insert(id, narrow(names.len() as u64)?);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        sizes.insert(NAMES, narrow(names.len() as u64)?);

        // SHA slots are package-relative, including zero slots before the image.
        // Solve the allocation dependency exactly, rather than copying L's size
        // estimate. Each increased reservation can only increase the body end.
        let mut sha_size = 0;
        loop {
            sizes.insert(PLAYGO_SHA, sha_size);
            let mut offset = BODY_START;
            let mut records = Vec::with_capacity(order.len());
            for &id in &order {
                let size = sizes[&id];
                let (flags1, flags2) = record_flags(id);
                records.push(Entry {
                    id,
                    name_offset: name_offsets.get(&id).copied().unwrap_or(0),
                    flags1,
                    flags2,
                    offset: narrow(offset)?,
                    size,
                });
                offset = align(add(offset, u64::from(size))?, ENTRY_ALIGNMENT)?;
            }
            let pfs_offset = align(offset, IMAGE_ALIGNMENT)?;
            // promote_size is BE32 even though image/package lengths are BE64.
            narrow(pfs_offset)?;
            let package_size = add(pfs_offset, pfs_size)?;
            let required_sha = narrow((package_size / BLOCK) * 4)?;
            if required_sha == sha_size {
                return Ok(Self {
                    records,
                    names,
                    pfs_offset,
                    package_size,
                });
            }
            sha_size = required_sha;
        }
    }

    pub fn records(&self) -> &[Entry] {
        &self.records
    }

    pub fn entry_names(&self) -> &[u8] {
        &self.names
    }

    pub fn body_range(&self) -> Range<u64> {
        BODY_START..self.pfs_offset
    }

    pub fn pfs_range(&self) -> Range<u64> {
        self.pfs_offset..self.package_size
    }

    /// Outer first-block hash input; full-image hash input is `pfs_range()`.
    pub fn pfs_signed_range(&self) -> Range<u64> {
        self.pfs_offset..self.pfs_offset + BLOCK
    }

    pub fn package_size(&self) -> u64 {
        self.package_size
    }

    /// Final METAS bytes, sorted by numeric ID. These exact records bind encrypted
    /// entry key/IV derivation; any later relocation requires re-encryption.
    pub fn entry_table(&self) -> Vec<u8> {
        let mut records: Vec<_> = self.records.iter().collect();
        records.sort_unstable_by_key(|e| e.id);
        let mut table = Vec::with_capacity(records.len() * RECORD_SIZE as usize);
        for e in records {
            for word in [e.id, e.name_offset, e.flags1, e.flags2, e.offset, e.size] {
                table.extend_from_slice(&word.to_be_bytes());
            }
            table.extend_from_slice(&[0; 8]);
        }
        table
    }

    /// (stored-byte hash input, digest-slot output), in ID order, excluding the
    /// DIGESTS self slot. Slot zero must remain zero. Padding is never entry data.
    /// Exception: NP binding's declared 0x214 bytes have 0x220 encrypted/hash bytes.
    pub fn entry_digest_ranges(&self) -> Vec<(Range<u64>, Range<u64>)> {
        let mut records: Vec<_> = self.records.iter().collect();
        records.sort_unstable_by_key(|e| e.id);
        let digest_offset = u64::from(self.record(DIGESTS).offset);
        records
            .iter()
            .enumerate()
            .skip(1)
            .map(|(index, e)| {
                let slot = digest_offset + index as u64 * RECORD_SIZE;
                (entry_range(e), slot..slot + RECORD_SIZE)
            })
            .collect()
    }

    /// Ordered concatenation inputs for SC hashes, NOT a contiguous padded range.
    /// Hash 2 includes only the first six ID-sorted METAS records.
    pub fn sc_digest_ranges(&self) -> [Vec<Range<u64>>; 2] {
        let first = MAIN_ORDER
            .iter()
            .map(|&id| entry_range(self.record(id)))
            .collect();
        let second = MAIN_ORDER[..4]
            .iter()
            .map(|&id| {
                let mut range = entry_range(self.record(id));
                if id == METAS {
                    range.end = range.start + SYSTEM_ORDER.len() as u64 * RECORD_SIZE;
                }
                range
            })
            .collect();
        [first, second]
    }

    fn record(&self, id: u32) -> &Entry {
        // Construction inserts every system record; fields cannot be mutated.
        self.records
            .iter()
            .find(|e| e.id == id)
            .expect("planned system record")
    }
}

pub(crate) fn entry_range(entry: &Entry) -> Range<u64> {
    let start = u64::from(entry.offset);
    let stored = if entry.id == 0x403 {
        entry.size.next_multiple_of(16)
    } else {
        entry.size
    };
    start..start + u64::from(stored)
}

fn record_name(id: u32) -> Option<&'static str> {
    match id {
        0x1000 => Some("param.sfo"),
        0x1001 => Some("playgo-chunk.dat"),
        PLAYGO_SHA => Some("playgo-chunk.sha"),
        0x1003 => Some("playgo-manifest.xml"),
        0x1004 => Some("pronunciation.xml"),
        0x1005 => Some("pronunciation.sig"),
        0x1006 => Some("pic1.png"),
        0x100d => Some("save_data.png"),
        0x1200 => Some("icon0.png"),
        0x1220 => Some("pic0.png"),
        0x1240 => Some("snd0.at9"),
        0x1260 => Some("changeinfo/changeinfo.xml"),
        0x1280 => Some("icon0.dds"),
        0x12a0 => Some("pic0.dds"),
        0x12c0 => Some("pic1.dds"),
        0x1400 => Some("trophy/trophy00.trp"),
        _ => None,
    }
}

fn record_flags(id: u32) -> (u32, u32) {
    match id {
        0x10 | 0x80 | METAS => (0x6000_0000, 0),
        0x20 => (0xe000_0000, 3 << 12),
        DIGESTS | NAMES => (0x4000_0000, 0),
        0x400 | 0x402 | 0x403 => (0x8000_0000, 3 << 12),
        0x401 => (0x8000_0000, 2 << 12),
        _ => (0, 0),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn narrow(value: u64) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| invalid("container offset/size exceeds BE32"))
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("container size overflow"))
}
fn align(value: u64, alignment: u64) -> io::Result<u64> {
    add(value, alignment - 1).map(|v| v / alignment * alignment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> Vec<RecordSize> {
        vec![
            RecordSize {
                id: 0x1000,
                size: 0x321,
            },
            RecordSize {
                id: 0x1003,
                size: 0x123,
            },
        ]
    }

    #[test]
    fn required_records_physical_order_flags_and_name_order() {
        let plan = BaseContainerLayout::plan(0x800000, &inputs()).unwrap();
        assert_eq!(plan.records.len(), 13);
        assert_eq!(
            &plan.records[..6].iter().map(|e| e.id).collect::<Vec<_>>(),
            &SYSTEM_ORDER
        );
        assert_eq!(plan.record(METAS).offset, 0x2a80);
        assert_eq!(plan.record(METAS).size, 13 * 32);
        assert_eq!(plan.record(0x20).flags1, 0xe0000000);
        assert_eq!(plan.record(0x20).key_index(), 3);
        assert_eq!(plan.record(0x400).size, 0x400);
        assert_eq!(plan.record(0x400).key_index(), 3);
        assert_eq!(plan.record(0x401).size, 0x200);
        assert_eq!(plan.record(0x401).key_index(), 2);
        assert_eq!(plan.record(0x409).size, 0x2000);
        assert_eq!(plan.record(PLAYGO_DAT).size, 416);
        assert_eq!(plan.body_range(), 0x2000..0x80000);
        assert_eq!(plan.pfs_range(), 0x80000..0x880000);
        assert_eq!(plan.pfs_signed_range(), 0x80000..0x90000);
        assert_eq!(plan.record(PLAYGO_SHA).size, 0x880000 / 0x10000 * 4);
        assert_eq!(
            plan.entry_names(),
            b"\0param.sfo\0playgo-chunk.dat\0playgo-chunk.sha\0playgo-manifest.xml\0"
        );
        for e in plan.records() {
            assert_eq!(e.offset % 16, 0);
            if let Some(name) = record_name(e.id) {
                let start = e.name_offset as usize;
                assert_eq!(
                    &plan.entry_names()[start..start + name.len()],
                    name.as_bytes()
                );
                assert_eq!(plan.entry_names()[start + name.len()], 0);
            } else {
                assert_eq!(e.name_offset, 0);
            }
        }
        for pair in plan.records.windows(2) {
            assert!(entry_range(&pair[0]).end <= u64::from(pair[1].offset));
        }
    }

    #[test]
    fn final_table_is_big_endian_id_sorted_with_zero_padding() {
        let plan = BaseContainerLayout::plan(BLOCK, &inputs()).unwrap();
        let table = plan.entry_table();
        assert_eq!(table.len(), plan.record(METAS).size as usize);
        assert_eq!(&table[..4], &DIGESTS.to_be_bytes());
        let mut ids = Vec::new();
        for row in table.as_chunks::<32>().0 {
            let id = u32::from_be_bytes(row[..4].try_into().unwrap());
            let e = plan.record(id);
            for (index, word) in [id, e.name_offset, e.flags1, e.flags2, e.offset, e.size]
                .iter()
                .enumerate()
            {
                assert_eq!(&row[index * 4..index * 4 + 4], &word.to_be_bytes());
            }
            assert_eq!(&row[24..], &[0; 8]);
            ids.push(id);
        }
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn integrity_ranges_exclude_self_padding_and_truncate_second_sc_table() {
        let plan = BaseContainerLayout::plan(BLOCK, &inputs()).unwrap();
        let ranges = plan.entry_digest_ranges();
        let digests = entry_range(plan.record(DIGESTS));
        assert_eq!(ranges.len(), plan.records.len() - 1);
        assert_eq!(ranges[0].0, entry_range(plan.record(0x10)));
        assert_eq!(ranges[0].1, digests.start + 32..digests.start + 64);
        assert_eq!(ranges.last().unwrap().1.end, digests.end);
        assert!(ranges.iter().all(|(input, _)| *input != digests));
        let [first, second] = plan.sc_digest_ranges();
        assert_eq!(first, MAIN_ORDER.map(|id| entry_range(plan.record(id))));
        assert_eq!(second[..3], first[..3]);
        assert_eq!(second[3].start, first[3].start);
        assert_eq!(second[3].end - second[3].start, 6 * RECORD_SIZE);
        assert_eq!(first[3].end - first[3].start, 13 * RECORD_SIZE);
        assert_eq!(first[4], digests);
    }

    #[test]
    fn input_order_does_not_change_layout() {
        let mut supplied = inputs();
        supplied.extend([
            RecordSize {
                id: 0x1240,
                size: 17,
            },
            RecordSize {
                id: 0x1006,
                size: 3,
            },
            RecordSize {
                id: 0x1200,
                size: 11,
            },
        ]);
        let a = BaseContainerLayout::plan(BLOCK, &supplied).unwrap();
        supplied.reverse();
        let b = BaseContainerLayout::plan(BLOCK, &supplied).unwrap();
        assert_eq!(a.entry_table(), b.entry_table());
        assert_eq!(a.entry_names(), b.entry_names());
        assert_eq!(a.package_size(), b.package_size());
    }

    #[test]
    fn required_and_unsupported_states_are_rejected() {
        for missing in 0..2 {
            let mut supplied = inputs();
            supplied.remove(missing);
            assert!(BaseContainerLayout::plan(BLOCK, &supplied).is_err());
        }
        for id in [
            PLAYGO_DAT,
            0x10,
            METAS,
            PLAYGO_SHA,
            0x400,
            0x401,
            0x409,
            0x402,
            0x1401,
            u32::MAX,
        ] {
            let mut supplied = inputs();
            supplied.push(RecordSize { id, size: 32 });
            assert!(BaseContainerLayout::plan(BLOCK, &supplied).is_err());
        }
        let mut duplicate = inputs();
        duplicate.push(duplicate[0]);
        assert!(BaseContainerLayout::plan(BLOCK, &duplicate).is_err());
    }

    #[test]
    fn malformed_and_unrepresentable_lengths_or_offsets_are_rejected() {
        for size in [0, 1, BLOCK - 1, BLOCK + 1, u64::MAX, u64::MAX - (BLOCK - 1)] {
            assert!(BaseContainerLayout::plan(size, &inputs()).is_err());
        }
        for size in [0, u64::from(crate::MAX_SFO_SIZE) + 1, u64::MAX] {
            let mut supplied = inputs();
            supplied[0].size = size;
            assert!(BaseContainerLayout::plan(BLOCK, &supplied).is_err());
        }
        for size in [u64::from(u32::MAX), u64::from(u32::MAX) + 1] {
            let mut supplied = inputs();
            supplied.push(RecordSize { id: 0x1240, size });
            // Even a representable record size can overflow later entry offsets
            // or the BE32 promote_size when aligned to the image boundary.
            assert!(BaseContainerLayout::plan(BLOCK, &supplied).is_err());
        }
        assert!(BaseContainerLayout::plan((u64::from(u32::MAX) + 1) * BLOCK, &inputs()).is_err());
    }

    #[test]
    fn source_confirmed_np_trophy_and_artwork_roles_are_retained() {
        let mut sizes = inputs();
        for (id, size) in [(0x402, 0xa0), (0x403, 0x214), (0x1400, 0x123)] {
            sizes.push(RecordSize { id, size });
        }
        for id in [0x1004, 0x1005, 0x100d, 0x1260, 0x1280, 0x12a0, 0x12c0] {
            sizes.push(RecordSize { id, size: 32 });
        }
        let layout = BaseContainerLayout::plan(BLOCK, &sizes).unwrap();
        for id in [0x402, 0x403] {
            let entry = layout.record(id);
            assert_eq!(
                (entry.flags1, entry.flags2, entry.name_offset),
                (0x80000000, 0x3000, 0)
            );
        }
        assert_eq!(layout.record(0x403).size, 0x214);
        assert_eq!(layout.record(0x1400).flags1, 0);
        assert!(
            layout
                .entry_names()
                .windows(b"trophy/trophy00.trp\0".len())
                .any(|s| s == b"trophy/trophy00.trp\0")
        );
        for (id, size) in [
            (0x402, 0x9f),
            (0x403, 0x220),
            (0x1400, u64::from(MAX_RESOURCE_SIZE) + 1),
        ] {
            let mut bad = sizes.clone();
            bad.iter_mut().find(|r| r.id == id).unwrap().size = size;
            assert!(BaseContainerLayout::plan(BLOCK, &bad).is_err());
        }
    }

    #[test]
    fn images_over_four_gib_and_sha_allocation_boundary() {
        let pfs_size = 5 * 1024 * 1024 * 1024;
        let plan = BaseContainerLayout::plan(pfs_size, &inputs()).unwrap();
        assert!(plan.package_size() > u64::from(u32::MAX));
        assert_eq!(plan.pfs_range().end - plan.pfs_range().start, pfs_size);
        assert_eq!(
            u64::from(plan.record(PLAYGO_SHA).size),
            plan.package_size() / BLOCK * 4
        );

        let mut supplied = inputs();
        supplied.push(RecordSize {
            id: 0x1240,
            size: 0x7a000,
        });
        // Without PlayGo SHA the body fits below 0x80000; its reservation pushes
        // the image across that boundary and changes SHA length a second time.
        let plan = BaseContainerLayout::plan(pfs_size, &supplied).unwrap();
        assert_eq!(plan.pfs_range().start, 0x100000);
        assert_eq!(
            u64::from(plan.record(PLAYGO_SHA).size),
            plan.package_size() / BLOCK * 4
        );
        let last = plan.records.last().unwrap();
        assert!(entry_range(last).end <= plan.pfs_range().start);
    }
}
