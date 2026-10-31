//! Source-backed GD base rebuild to a fresh legacy image. No identity generation.
//!
//! Sources and destination parents must remain stable: metadata plus whole-source
//! hashing detects ordinary changes, not hostile concurrent mutation. Publication
//! requires hard links; no existing output is replaced. Console acceptance remains
//! separate from structural and byte-preservation checks.

use crate::{
    FileKind, Game, Package,
    container::{self, BaseContainerLayout, DEFAULT_PLAYGO_MANIFEST, RecordSize, SourceCrypto},
    inner_image::{self, InnerImage},
    outer_image::OuterImage,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

const BLOCK: usize = 65536;
const LEGACY_PFS_FLAGS: u64 = 0x8000_0000_0000_03cc;
const NEWCRYPT_PFS_FLAGS: u64 = 0xa000_0000_0000_03cc;

#[derive(Clone, Copy)]
enum SourceProfile {
    Legacy,
    Newcrypt2019,
}

impl SourceProfile {
    fn from_header(header: &crate::Header) -> io::Result<Self> {
        match (header.flags, header.pfs_flags) {
            (1, LEGACY_PFS_FLAGS) => Ok(Self::Legacy),
            (0x4000_0001, NEWCRYPT_PFS_FLAGS) => Ok(Self::Newcrypt2019),
            _ => Err(invalid("unsupported source GD rebuild profile")),
        }
    }

    fn apply(self, header: &mut [u8; 0x1000]) {
        if matches!(self, Self::Newcrypt2019) {
            put32(header, 4, 0x4000_0001);
            put32(header, 0x80, 0x2019_0801);
            put32(header, 0x84, 0x0ea8_a9bd);
            put32(header, 0x43c, 0x12_0000);
            put64(header, 0x408, NEWCRYPT_PFS_FLAGS);
        }
    }
}
/// Conventional FPKG passcode, tried and verified against source ENTRY_KEYS.
pub const DEFAULT_PASSCODE: [u8; 32] = [b'0'; 32];

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn pkg_error(error: crate::Error) -> io::Error {
    match error {
        crate::Error::Io(error) => error,
        crate::Error::Cancelled => io::Error::new(io::ErrorKind::Interrupted, error),
        _ => invalid(&error.to_string()),
    }
}

fn fake_header(digest: &[u8; 32]) -> io::Result<[u8; 256]> {
    use rsa::traits::PublicKeyParts;
    // Header fake-signing modulus is package-key slot 3, not IMAGE_KEY's modulus.
    let modulus: [u8; 256] = crate::crypto::rsa_key(false)
        .n()
        .to_bytes_be()
        .try_into()
        .map_err(|_| invalid("fixed public modulus width"))?;
    container::public_rsa_wrap(&modulus, &[1, 0, 1], digest)
}

#[derive(PartialEq, Eq)]
struct Stamp(u64, u64, u64, i64, i64, i64, i64);
fn stamp(m: &Metadata) -> Stamp {
    Stamp(
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn hash_source(file: &mut File, cancelled: &mut impl FnMut() -> bool) -> io::Result<[u8; 32]> {
    file.rewind()?;
    let mut hash = Sha256::new();
    let mut buffer = [0; BLOCK];
    loop {
        inner_image::check(cancelled)?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

fn read_record(
    package: &mut Package<File>,
    id: u32,
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<Vec<u8>> {
    package
        .read_authoring_record(id, crate::authoring::MAX_RECORD_SIZE, cancelled)
        .map_err(pkg_error)?
        .ok_or_else(|| invalid("required source container record is missing"))
}

fn record(plan: &BaseContainerLayout, id: u32) -> io::Result<&crate::Entry> {
    plan.records()
        .iter()
        .find(|e| e.id == id)
        .ok_or_else(|| invalid("missing planned record"))
}

fn put_record(
    file: &mut File,
    plan: &BaseContainerLayout,
    id: u32,
    bytes: &[u8],
) -> io::Result<()> {
    let entry = record(plan, id)?;
    let stored = container::entry_range(entry);
    if bytes.len() as u64 != stored.end - stored.start {
        return Err(invalid("final record size mismatch"));
    }
    file.seek(SeekFrom::Start(u64::from(entry.offset)))?;
    file.write_all(bytes)
}

fn put32(header: &mut [u8], offset: usize, value: u32) {
    header[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn put64(header: &mut [u8], offset: usize, value: u64) {
    header[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn header(plan: &BaseContainerLayout, content_id: &str) -> io::Result<[u8; 0x1000]> {
    let mut header = [0; 0x1000];
    header[..4].copy_from_slice(b"\x7fCNT");
    header[0x40..0x64].copy_from_slice(content_id.as_bytes());
    let count = plan.records().len() as u32;
    for (offset, value) in [
        (4, 1),
        (0xc, 15),
        (0x10, count),
        (0x18, record(plan, 0x100)?.offset),
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
        (0x7c, plan.pfs_range().start as u32),
        (0x80, 0x20161020),
        (0x84, 0x01738551),
        (0x9c, 1),
        (0x400, 1),
        (0x404, 1),
        (0x438, 0x10000),
        (0x43c, 0xd0000),
    ] {
        put32(&mut header, offset, value);
    }
    header[0x14..0x16].copy_from_slice(&6u16.to_be_bytes());
    header[0x16..0x18].copy_from_slice(&(count as u16).to_be_bytes());
    for (offset, value) in [
        (0x20, plan.body_range().start),
        (0x28, plan.body_range().end - plan.body_range().start),
        (0x408, 0x80000000000003cc),
        (0x410, plan.pfs_range().start),
        (0x418, plan.pfs_range().end - plan.pfs_range().start),
        (0x428, plan.package_size()),
        (0x430, plan.package_size()),
    ] {
        put64(&mut header, offset, value);
    }
    Ok(header)
}

// Ignore encoding, BOM, indentation and attribute order, not unknown settings.
fn default_manifest(bytes: &[u8]) -> bool {
    fn shape(node: roxmltree::Node<'_, '_>, out: &mut Vec<String>) {
        if node.is_element() {
            out.push(format!(
                "{:?}:{}",
                node.tag_name().namespace(),
                node.tag_name().name()
            ));
            let mut attrs: Vec<_> = node
                .attributes()
                .map(|a| format!("{:?}:{}={}", a.namespace(), a.name(), a.value()))
                .collect();
            attrs.sort();
            out.extend(attrs);
            for child in node.children() {
                shape(child, out);
            }
            out.push("/".into());
        } else if let Some(text) = node.text().filter(|s| !s.trim().is_empty()) {
            out.push(text.trim().into());
        }
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(actual) = roxmltree::Document::parse(text.trim_start_matches('\u{feff}')) else {
        return false;
    };
    let Ok(expected) = roxmltree::Document::parse(DEFAULT_PLAYGO_MANIFEST) else {
        return false;
    };
    let mut a = Vec::new();
    let mut b = Vec::new();
    shape(actual.root_element(), &mut a);
    shape(expected.root_element(), &mut b);
    a == b
}

fn default_dat(
    plan: &BaseContainerLayout,
    content_id: &str,
    inner_size: u64,
    package_size: u64,
    source: &[u8],
) -> io::Result<[u8; 416]> {
    if source.len() != 416 || inner_size == 0 || !inner_size.is_multiple_of(BLOCK as u64) {
        return Err(invalid(
            "unsupported PlayGo DAT length or decoded inner size",
        ));
    }
    // F playgo.c:101-110,223-228 identifies version/SDK as header metadata,
    // separate from chunk/scenario scheduling. Preserve these exact source bytes.
    let modern = source[4..8] == [0, 0x30, 0, 0];
    if !modern && (source[4..8] != [0; 4] || source[24..28] != [0; 4]) {
        return Err(invalid("unsupported PlayGo DAT version"));
    }
    // Compressed source PFSC can decode larger than the stored outer image.
    let mut dat = plan.playgo_dat(content_id, BLOCK as u64)?;
    dat[4..8].copy_from_slice(&source[4..8]);
    dat[24..28].copy_from_slice(&source[24..28]);
    dat[0x148..0x150].copy_from_slice(&package_size.to_le_bytes());
    dat[0x158..0x160].copy_from_slice(&inner_size.to_le_bytes());
    Ok(dat)
}

/// Rebuild only the supported single-image/default-PlayGo GD base profile.
/// Preserves SFO, original licenses, ENTRY_KEYS, executable bytes and keystone.
/// Rejects unsupported content before scratch, validates complete source integrity,
/// regenerates both images/container records, reopens and compares every retained
/// application byte, then rehashes source before no-overwrite publication.
pub fn rebuild_new(
    source: &Path,
    destination: &Path,
    passcode: &[u8; 32],
    mut cancelled: impl FnMut() -> bool,
) -> io::Result<()> {
    inner_image::check(&mut cancelled)?;
    if destination.extension().and_then(|e| e.to_str()) != Some("pkg") {
        return Err(invalid("rebuild output requires .pkg extension"));
    }
    let source = crate::gp4::absolute(source)?;
    crate::gp4::no_symlinks(&source)?;
    let destination = crate::gp4::absolute(destination)?;
    if source == destination {
        return Err(invalid("source and output overlap"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("output has no parent"))?;
    crate::gp4::no_symlinks(parent)?;
    let parent_identity = fs::metadata(parent)?;
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "rebuild output exists",
        ));
    }
    let source_parent = source
        .parent()
        .ok_or_else(|| invalid("source has no parent"))?;
    let root = pkg_fs::SourceRoot::open(source_parent)?;
    let relative = Path::new(
        source
            .file_name()
            .ok_or_else(|| invalid("source has no filename"))?,
    );
    let mut file = root.open_file(relative)?;
    let before = stamp(&file.metadata()?);
    let mut package = Package::open(file.try_clone()?).map_err(pkg_error)?;
    let source_profile = SourceProfile::from_header(package.header())?;
    let mut original_header = [0; 0x1000];
    file.rewind()?;
    file.read_exact(&mut original_header)?;
    let sfo = read_record(&mut package, 0x1000, &mut cancelled)?;
    let identity = crate::gp4::sfo_identity(&sfo)?;
    if package.header().content_id[..36] != *identity.content_id.as_bytes()
        || package.header().content_id[36..].iter().any(|&b| b != 0)
    {
        return Err(invalid("source header content ID disagrees with SFO"));
    }
    let mut sizes = Vec::new();
    for e in package.entries() {
        match e.id {
            id if crate::extract::metadata_name(id).is_some() && !matches!(id, 0x1001 | 0x1002) => {
                sizes.push(RecordSize {
                    id: e.id,
                    size: u64::from(e.size),
                })
            }
            1 | 0x10 | 0x20 | 0x80 | 0x100 | 0x200 | 0x400 | 0x401 | 0x409 | 0x1001 | 0x1002 => (),
            _ => {
                return Err(invalid(&format!(
                    "unsupported source container record {:#x}; unknown resources cannot be dropped",
                    e.id
                )));
            }
        }
    }
    let original_plan = BaseContainerLayout::plan(package.header().pfs_size, &sizes)?;
    if package.entries().len() != original_plan.records().len() {
        return Err(invalid(
            "unsupported source record layout or resource identities",
        ));
    }
    // Source physical order/name offsets need not equal the fresh destination.
    for e in package.entries() {
        let expected = record(&original_plan, e.id)?;
        if (e.flags1, e.flags2, e.size) != (expected.flags1, expected.flags2, expected.size) {
            return Err(invalid("unsupported source record flags or length"));
        }
    }
    if read_record(&mut package, 0x409, &mut cancelled)?
        .iter()
        .any(|&b| b != 0)
    {
        return Err(invalid("unsupported nonzero psreserved.dat"));
    }
    let manifest = read_record(&mut package, 0x1003, &mut cancelled)?;
    if !default_manifest(&manifest) {
        return Err(invalid("unsupported custom PlayGo manifest"));
    }
    let dat = read_record(&mut package, 0x1001, &mut cancelled)?;
    if dat.len() != 416 {
        return Err(invalid("unsupported PlayGo DAT length"));
    }
    let inner_size = u64::from_le_bytes(
        dat[0x158..0x160]
            .try_into()
            .map_err(|_| invalid("PlayGo size"))?,
    );
    let expected_dat = default_dat(
        &original_plan,
        &identity.content_id,
        inner_size,
        package.header().package_size,
        &dat,
    )?;
    if expected_dat.as_slice() != dat {
        return Err(invalid(
            "unsupported custom PlayGo scheduling or wrong image sizes",
        ));
    }
    inner_image::check(&mut cancelled)?;
    let passcode = std::str::from_utf8(passcode)
        .map_err(|_| invalid("passcode must contain 32 printable ASCII bytes"))?;
    let crypto = SourceCrypto::from_package(&mut package, passcode)?;
    if matches!(source_profile, SourceProfile::Newcrypt2019) {
        let mut seed = [0; 16];
        file.seek(SeekFrom::Start(package.header().pfs_offset + 0x370))?;
        file.read_exact(&mut seed)?;
        if crate::crypto::hmac(crypto.image_key(), &seed) != *crypto.source_image_key() {
            return Err(invalid(
                "source newcrypt IMAGE_KEY disagrees with candidate and seed",
            ));
        }
    }
    inner_image::check(&mut cancelled)?;
    let fingerprint = hash_source(&mut file, &mut cancelled)?;
    if stamp(&file.metadata()?) != before {
        return Err(invalid("source changed while preparing rebuild"));
    }
    validate_source_container(
        &mut package,
        &mut file,
        &original_plan,
        &original_header,
        &sfo,
        source_profile,
        &mut cancelled,
    )?;
    let mut game = package.open_rebuild_game().map_err(pkg_error)?;
    if game.inner_image_size() != inner_size {
        return Err(invalid("PlayGo inner size disagrees with actual image"));
    }
    let mut entries = Vec::new();
    let mut indices = Vec::new();
    let mut keystone = false;
    let mut executable = false;
    for (index, e) in game.entries().iter().enumerate() {
        inner_image::check(&mut cancelled)?;
        if e.is_container() {
            continue;
        }
        if e.kind() == FileKind::File {
            if e.path() == "sce_sys/keystone" {
                keystone = e.size() == 96;
            } else if e.path() == "eboot.bin" {
                executable = e.size() != 0;
            }
        }
        entries.push(inner_image::Entry {
            path: e.path().into(),
            size: (e.kind() == FileKind::File).then_some(e.size()),
        });
        indices.push(index);
    }
    if !keystone || !executable {
        return Err(invalid(
            "rebuild requires original 96-byte keystone and nonempty eboot.bin",
        ));
    }
    // Deterministic image timestamps; application contents/SFO remain unchanged.
    let inner = InnerImage::new(&entries, 0)?;
    let outer = OuterImage::new(&inner, 0)?;
    let original_sizes = sizes.clone();
    for size in &mut sizes {
        if size.id == 0x1003 {
            size.size = DEFAULT_PLAYGO_MANIFEST.len() as u64;
        }
    }
    let plan = BaseContainerLayout::plan(outer.pfs_size(), &sizes)?;
    let mut final_header = header(&plan, &identity.content_id)?;
    // Validate all general-digest SFO fields before allocating package scratch.
    container::general_digests(&final_header, &sfo)?;
    if stamp(&file.metadata()?) != before || hash_source(&mut file, &mut cancelled)? != fingerprint
    {
        return Err(invalid("source changed before rebuild scratch"));
    }
    inner_image::publish(&destination, |output| {
        output.set_len(plan.pfs_range().start)?;
        output.seek(SeekFrom::Start(plan.pfs_range().start))?;
        outer.write(
            &mut OffsetFile {
                file: output,
                base: plan.pfs_range().start,
            },
            crypto.image_key(),
            |i, offset, bytes| {
                let mut reader = game.read_entry(indices[i]).map_err(pkg_error)?;
                reader.seek(SeekFrom::Start(offset))?;
                reader.read_exact(bytes)
            },
            &mut cancelled,
        )?;
        for (id, bytes) in crypto.encrypt_for_layout(&plan)? {
            put_record(output, &plan, id, &bytes)?;
        }
        put_record(output, &plan, 0x100, &plan.entry_table())?;
        put_record(output, &plan, 0x200, plan.entry_names())?;
        put_record(output, &plan, 0x409, &[0; 0x2000])?;
        put_record(output, &plan, 0x1000, &sfo)?;
        put_record(
            output,
            &plan,
            0x1001,
            &default_dat(
                &plan,
                &identity.content_id,
                inner.pfs_size(),
                plan.package_size(),
                &dat,
            )?,
        )?;
        put_record(output, &plan, 0x1003, DEFAULT_PLAYGO_MANIFEST.as_bytes())?;
        for resource in &original_sizes {
            if matches!(resource.id, 0x402 | 0x403 | 0x1000 | 0x1003) {
                continue;
            }
            let target = crate::extract::metadata_name(resource.id)
                .ok_or_else(|| invalid("resource name"))?;
            let index = game
                .entries()
                .iter()
                .position(|e| e.path() == format!("sce_sys/{target}"))
                .ok_or_else(|| invalid("source resource missing"))?;
            output.seek(SeekFrom::Start(u64::from(
                record(&plan, resource.id)?.offset,
            )))?;
            copy_entry(&mut game, index, output, &mut cancelled)?;
        }
        // Separate file descriptor's cursor is reset per write; never clone a
        // shared-offset File for concurrent read/write PlayGo streaming.
        let pfs = write_sha(output, &plan, &mut cancelled)?;
        final_header[0x440..0x460].copy_from_slice(&pfs.image);
        final_header[0x460..0x480].copy_from_slice(&pfs.first_block);
        put_record(
            output,
            &plan,
            0x80,
            &container::general_digests(&final_header, &sfo)?,
        )?;
        let digests = plan.entry_digests(output, &mut cancelled)?;
        put_record(output, &plan, 1, &digests)?;
        let body = plan.body_digests(output, &mut cancelled)?;
        for (offset, hash) in [
            (0x100, body.sc_entries1),
            (0x120, body.sc_entries2),
            (0x140, body.digest_table),
            (0x160, body.body),
        ] {
            final_header[offset..offset + 32].copy_from_slice(&hash);
        }
        let digest = container::header_digest(&final_header);
        final_header[0xfe0..].copy_from_slice(&digest);
        output.rewind()?;
        output.write_all(&final_header)?;
        output.write_all(&fake_header(&container::signature_digest(&final_header)?)?)?;
        output.sync_all()?;
        validate_container(output, &plan, &final_header, &sfo, &mut cancelled)?;
        compare_payloads(&mut game, output, &mut cancelled)?;
        let mut current = root.open_file(relative)?;
        if stamp(&current.metadata()?) != before
            || hash_source(&mut current, &mut cancelled)? != fingerprint
            || stamp(&current.metadata()?) != before
            || stamp(&file.metadata()?) != before
        {
            return Err(invalid("source changed during rebuild"));
        }
        crate::gp4::no_symlinks(parent)?;
        let current_parent = fs::metadata(parent)?;
        if (current_parent.dev(), current_parent.ino())
            != (parent_identity.dev(), parent_identity.ino())
        {
            return Err(invalid("destination parent changed during rebuild"));
        }
        inner_image::check(&mut cancelled)
    })
}

fn copy_entry(
    game: &mut Game<File>,
    index: usize,
    output: &mut impl Write,
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<()> {
    let mut reader = game.read_entry(index).map_err(pkg_error)?;
    let mut bytes = [0; BLOCK];
    loop {
        inner_image::check(cancelled)?;
        let count = reader.read(&mut bytes)?;
        if count == 0 {
            return Ok(());
        }
        output.write_all(&bytes[..count])?;
    }
}

// Seek-relative window permits image writer's image-relative offsets in one scratch.
struct OffsetFile<'a> {
    file: &'a mut File,
    base: u64,
}
impl Read for OffsetFile<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.file.read(b)
    }
}
impl Write for OffsetFile<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.file.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for OffsetFile<'_> {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        let position = match p {
            SeekFrom::Start(n) => self
                .base
                .checked_add(n)
                .ok_or_else(|| invalid("image seek overflow"))?,
            SeekFrom::Current(n) => self
                .file
                .stream_position()?
                .checked_add_signed(n)
                .ok_or_else(|| invalid("image seek overflow"))?,
            SeekFrom::End(n) => self
                .file
                .metadata()?
                .len()
                .checked_add_signed(n)
                .ok_or_else(|| invalid("image seek overflow"))?,
        };
        if position < self.base {
            return Err(invalid("image seek before window"));
        }
        self.file.seek(SeekFrom::Start(position))?;
        Ok(position - self.base)
    }
}

fn write_sha(
    file: &mut File,
    plan: &BaseContainerLayout,
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<container::PfsDigests> {
    let mut bytes = [0; BLOCK];
    let mut full = Sha256::new();
    let mut first = [0; 32];
    let entry = record(plan, 0x1002)?;
    for offset in (plan.pfs_range().start..plan.package_size()).step_by(BLOCK) {
        inner_image::check(cancelled)?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut bytes)?;
        full.update(bytes);
        let digest = Sha256::digest(bytes);
        if offset == plan.pfs_range().start {
            first.copy_from_slice(&digest);
        }
        file.seek(SeekFrom::Start(
            u64::from(entry.offset) + offset / BLOCK as u64 * 4,
        ))?;
        file.write_all(&digest[..4])?;
    }
    Ok(container::PfsDigests {
        first_block: first,
        image: full.finalize().into(),
    })
}

fn validate_container(
    file: &mut File,
    plan: &BaseContainerLayout,
    actual: &[u8; 0x1000],
    sfo: &[u8],
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<()> {
    let mut package = Package::open(file.try_clone()?).map_err(pkg_error)?;
    let content_id = crate::gp4::sfo_identity(sfo)?.content_id;
    let mut expected = header(plan, &content_id)?;
    // Compare full PlayGo SHA without allocating payload-proportional tables.
    struct Slots<'a> {
        file: &'a File,
        offset: u64,
        end: u64,
    }
    impl Write for Slots<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            use std::os::unix::fs::FileExt;
            if self.offset + bytes.len() as u64 > self.end {
                return Err(invalid("PlayGo SHA overflow"));
            }
            let mut stored = [0; 4];
            if bytes.len() != 4 {
                return Err(invalid("PlayGo SHA slot size"));
            }
            self.file.read_exact_at(&mut stored, self.offset)?;
            if stored != bytes {
                return Err(invalid("PlayGo SHA mismatch"));
            }
            self.offset += 4;
            Ok(4)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let sha = record(plan, 0x1002)?;
    let reader = file.try_clone()?;
    let mut slots = Slots {
        file: &reader,
        offset: u64::from(sha.offset),
        end: u64::from(sha.offset) + u64::from(sha.size),
    };
    let pfs = plan.write_playgo_sha(file, &mut slots, &mut *cancelled)?;
    if slots.offset != slots.end {
        return Err(invalid("PlayGo SHA length mismatch"));
    }
    expected[0x440..0x460].copy_from_slice(&pfs.image);
    expected[0x460..0x480].copy_from_slice(&pfs.first_block);
    if read_record(&mut package, 0x80, cancelled)? != container::general_digests(&expected, sfo)?
        || read_record(&mut package, 1, cancelled)? != plan.entry_digests(file, &mut *cancelled)?
    {
        return Err(invalid("source/final container record digest mismatch"));
    }
    let body = plan.body_digests(file, &mut *cancelled)?;
    for (offset, hash) in [
        (0x100, body.sc_entries1),
        (0x120, body.sc_entries2),
        (0x140, body.digest_table),
        (0x160, body.body),
    ] {
        expected[offset..offset + 32].copy_from_slice(&hash);
    }
    let digest = container::header_digest(&expected);
    expected[0xfe0..].copy_from_slice(&digest);
    if expected != *actual {
        return Err(invalid(
            "unsupported source header profile or container integrity mismatch",
        ));
    }
    let mut signature = [0; 256];
    file.seek(SeekFrom::Start(0x1000))?;
    file.read_exact(&mut signature)?;
    if signature != fake_header(&container::signature_digest(actual)?)? {
        return Err(invalid("fake header mismatch"));
    }
    Ok(())
}

fn hash_ranges(
    file: &mut File,
    ranges: &[std::ops::Range<u64>],
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = [0; BLOCK];
    for range in ranges {
        file.seek(SeekFrom::Start(range.start))?;
        let mut left = range.end - range.start;
        while left != 0 {
            inner_image::check(cancelled)?;
            let count = left.min(BLOCK as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            left -= count as u64;
        }
    }
    Ok(hash.finalize().into())
}

// Validate source placement independently of destination's canonical allocation.
fn validate_source_container(
    package: &mut Package<File>,
    file: &mut File,
    plan: &BaseContainerLayout,
    actual: &[u8; 0x1000],
    sfo: &[u8],
    profile: SourceProfile,
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<()> {
    let entries = package.entries().to_vec();
    let h = package.header();
    let (entry_table_offset, pfs_offset, pfs_size, package_size) = (
        h.entry_table_offset,
        h.pfs_offset,
        h.pfs_size,
        h.package_size,
    );
    let find = |id| {
        entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| invalid("source record missing"))
    };
    let range = |id| -> io::Result<std::ops::Range<u64>> {
        let e = find(id)?;
        Ok(container::entry_range(e))
    };
    if entries.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || entry_table_offset != find(0x100)?.offset
        || pfs_offset + pfs_size != package_size
        || package_size != file.metadata()?.len()
        || !pfs_offset.is_multiple_of(0x80000)
    {
        return Err(invalid("unsupported source table/image boundaries"));
    }
    let mut allocated: Vec<_> = entries.iter().collect();
    allocated.sort_by_key(|e| e.offset);
    let mut end = 0x2000;
    for e in &allocated {
        if u64::from(e.offset) < end || !e.offset.is_multiple_of(16) {
            return Err(invalid("overlapping or unaligned source records"));
        }
        end = container::entry_range(e).end;
        if end > pfs_offset {
            return Err(invalid("source record exceeds body"));
        }
    }
    if allocated
        .iter()
        .take(6)
        .map(|e| e.id)
        .ne([0x10, 0x20, 0x80, 0x100, 1, 0x200])
        || allocated[0].offset != 0x2000
    {
        return Err(invalid("unsupported source system record order"));
    }
    let names = read_record(package, 0x200, cancelled)?;
    if names.first() != Some(&0) {
        return Err(invalid("source names lack empty name"));
    }
    let name_at = |names: &[u8], offset: u32| -> io::Result<Vec<u8>> {
        let offset = offset as usize;
        if offset >= names.len() || (offset != 0 && names[offset - 1] != 0) {
            return Err(invalid("invalid source name boundary"));
        }
        let tail = &names[offset..];
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| invalid("unterminated source name"))?;
        Ok(tail[..end].to_vec())
    };
    let mut table = Vec::new();
    for e in &entries {
        let expected = record(plan, e.id)?;
        if name_at(&names, e.name_offset)? != name_at(plan.entry_names(), expected.name_offset)? {
            return Err(invalid("unsupported source resource identity"));
        }
        for word in [
            e.id,
            e.name_offset,
            e.flags1,
            e.flags2,
            e.offset,
            e.size,
            0,
            0,
        ] {
            table.extend_from_slice(&word.to_be_bytes());
        }
    }
    if read_record(package, 0x100, cancelled)? != table {
        return Err(invalid("source table reserved bytes or METAS mismatch"));
    }
    let mut expected = header(plan, &crate::gp4::sfo_identity(sfo)?.content_id)?;
    profile.apply(&mut expected);
    for (offset, value) in [
        (0x18, entry_table_offset),
        (
            0x7c,
            u32::try_from(pfs_offset).map_err(|_| invalid("source promote size"))?,
        ),
    ] {
        put32(&mut expected, offset, value);
    }
    for (offset, value) in [
        (0x28, pfs_offset - 0x2000),
        (0x410, pfs_offset),
        (0x418, pfs_size),
        (0x428, package_size),
        (0x430, package_size),
    ] {
        put64(&mut expected, offset, value);
    }
    let sha_entry = find(0x1002)?;
    if u64::from(sha_entry.size) != package_size / BLOCK as u64 * 4 {
        return Err(invalid("source PlayGo SHA length"));
    }
    let mut bytes = [0; BLOCK];
    let mut full = Sha256::new();
    for block in 0..package_size / BLOCK as u64 {
        inner_image::check(cancelled)?;
        let offset = block * BLOCK as u64;
        let mut digest = [0; 4];
        if offset >= pfs_offset {
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut bytes)?;
            full.update(bytes);
            let hash = Sha256::digest(bytes);
            digest.copy_from_slice(&hash[..4]);
            if offset == pfs_offset {
                expected[0x460..0x480].copy_from_slice(&hash);
            }
        }
        file.seek(SeekFrom::Start(u64::from(sha_entry.offset) + block * 4))?;
        let mut stored = [0; 4];
        file.read_exact(&mut stored)?;
        if stored != digest {
            return Err(invalid("source PlayGo SHA mismatch"));
        }
    }
    expected[0x440..0x460].copy_from_slice(&full.finalize());
    let digests = read_record(package, 1, cancelled)?;
    if digests[..32] != [0; 32] {
        return Err(invalid("source digest self slot"));
    }
    for (index, e) in entries.iter().enumerate().skip(1) {
        if hash_ranges(file, &[range(e.id)?], cancelled)? != digests[index * 32..(index + 1) * 32] {
            return Err(invalid("source record digest mismatch"));
        }
    }
    if read_record(package, 0x80, cancelled)? != container::general_digests(&expected, sfo)? {
        return Err(invalid(
            "unsupported source general-digest recipe or integrity mismatch; System/PlayGo/Trophy and alternate MajorParam/Content recipes remain unverified",
        ));
    }
    for (offset, ids) in [
        (0x100, &[0x10, 0x20, 0x80, 0x100, 1][..]),
        (0x120, &[0x10, 0x20, 0x80, 0x100][..]),
    ] {
        let mut ranges: Vec<_> = ids.iter().map(|&id| range(id)).collect::<io::Result<_>>()?;
        if offset == 0x120 {
            let last = ranges
                .last_mut()
                .ok_or_else(|| invalid("source SC ranges"))?;
            last.end = last.start + 6 * 32;
        }
        expected[offset..offset + 32].copy_from_slice(&hash_ranges(file, &ranges, cancelled)?);
    }
    expected[0x140..0x160].copy_from_slice(&Sha256::digest(&digests));
    let body_range = 0x2000..pfs_offset;
    expected[0x160..0x180].copy_from_slice(&hash_ranges(
        file,
        std::slice::from_ref(&body_range),
        cancelled,
    )?);
    let digest = container::header_digest(&expected);
    expected[0xfe0..].copy_from_slice(&digest);
    if expected != *actual {
        return Err(invalid(
            "unsupported source header profile or container integrity mismatch",
        ));
    }
    let mut signature = [0; 256];
    file.seek(SeekFrom::Start(0x1000))?;
    file.read_exact(&mut signature)?;
    if signature != fake_header(&container::signature_digest(actual)?)? {
        return Err(invalid("source fake header mismatch"));
    }
    Ok(())
}

fn compare_payloads(
    source: &mut Game<File>,
    file: &mut File,
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<()> {
    let mut rebuilt = Package::open(file.try_clone()?)
        .map_err(pkg_error)?
        .open_rebuild_game()
        .map_err(pkg_error)?;
    if source.entries().len() != rebuilt.entries().len() {
        return Err(invalid("rebuilt namespace changed"));
    }
    let mut a = [0; BLOCK];
    let mut b = [0; BLOCK];
    for i in 0..source.entries().len() {
        inner_image::check(cancelled)?;
        let left = &source.entries()[i];
        let right = &rebuilt.entries()[i];
        if left.path() != right.path()
            || left.kind() != right.kind()
            || left.is_container() != right.is_container()
        {
            return Err(invalid("rebuilt namespace changed"));
        }
        if left.kind() == FileKind::Directory {
            continue;
        }
        if matches!(
            left.path(),
            "sce_sys/playgo-chunk.dat" | "sce_sys/playgo-chunk.sha" | "sce_sys/playgo-manifest.xml"
        ) {
            continue;
        }
        if left.size() != right.size() {
            return Err(invalid("rebuilt payload size changed"));
        }
        let size = left.size();
        let mut left = source.read_entry(i).map_err(pkg_error)?;
        let mut right = rebuilt.read_entry(i).map_err(pkg_error)?;
        let mut remaining = size;
        while remaining != 0 {
            inner_image::check(cancelled)?;
            let count = remaining.min(BLOCK as u64) as usize;
            left.read_exact(&mut a[..count])?;
            right.read_exact(&mut b[..count])?;
            if a[..count] != b[..count] {
                return Err(invalid("rebuilt payload bytes changed"));
            }
            remaining -= count as u64;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_dat_preserves_known_version_sdk_not_custom_scheduling() {
        let id = "ZZ0000-CUSA00000_00-SYNTHETIC0000000";
        let plan = BaseContainerLayout::plan(
            BLOCK as u64,
            &[
                RecordSize {
                    id: 0x1000,
                    size: 32,
                },
                RecordSize {
                    id: 0x1003,
                    size: 32,
                },
            ],
        )
        .unwrap();
        let mut source = plan.playgo_dat(id, BLOCK as u64).unwrap();
        source[4..8].copy_from_slice(&[0, 0x30, 0, 0]);
        source[24..28].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let rebuilt = default_dat(&plan, id, 2 * BLOCK as u64, 10 * BLOCK as u64, &source).unwrap();
        assert_eq!(rebuilt[4..8], source[4..8]);
        assert_eq!(rebuilt[24..28], source[24..28]);
        assert_eq!(rebuilt[0x158..0x160], (2 * BLOCK as u64).to_le_bytes());
        assert!(default_dat(&plan, id, 0, 10 * BLOCK as u64, &source).is_err());
        source[4] = 1;
        assert!(default_dat(&plan, id, BLOCK as u64, plan.package_size(), &source).is_err());
        source[4] = 0;
        source[0x102] = 2;
        assert_ne!(
            default_dat(&plan, id, BLOCK as u64, plan.package_size(), &source).unwrap(),
            source
        );
    }

    #[test]
    fn custom_manifest_is_not_silently_replaced() {
        assert!(default_manifest(DEFAULT_PLAYGO_MANIFEST.as_bytes()));
        assert!(default_manifest(
            format!(
                "\u{feff}{}",
                DEFAULT_PLAYGO_MANIFEST.replace("><", ">\r\n<")
            )
            .as_bytes()
        ));
        assert!(!default_manifest(
            DEFAULT_PLAYGO_MANIFEST
                .replace("Scenario #0", "custom")
                .as_bytes()
        ));
        assert!(!default_manifest(
            DEFAULT_PLAYGO_MANIFEST
                .replace("<volume>", "<volume><unknown/>")
                .as_bytes()
        ));
    }
    #[test]
    fn cancellation_precedes_any_source_or_output_io() {
        let error = rebuild_new(
            Path::new("missing.pkg"),
            Path::new("unused.pkg"),
            &DEFAULT_PASSCODE,
            || true,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }
}
