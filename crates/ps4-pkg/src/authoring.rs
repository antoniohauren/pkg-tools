//! Authoring inventory and narrow GP4 source preparation, not a native PKG writer.
//! Unix [`PreparedProject`] connects approved sources to inner and outer images.
//!
//! GP4 schema/source approval is necessary but does not establish rebuild readiness.
//! This inventory keeps unsupported resources visible instead of silently dropping
//! them. GP4 reports contain no passcode, payload, keys or fingerprints. Package
//! inventories retain sensitive original metadata privately, without Debug output.

use crate::gp4::{Identity, Project, SourceReference};

#[cfg(unix)]
mod sources;
#[cfg(unix)]
pub use sources::{Placement, PreparedProject, PreparedResource};
use std::{
    fs, io,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::{Entry, Error, FileKind, Package, crypto, extract, input::ReadAt};

const KEYSTONE_SIZE: u64 = 96;

/// Gates for directory/GP4 authoring, distinct from source-backed `rebuild`.
pub const WRITER_BLOCKERS: &[&str] = &[
    "directory/GP4-to-PKG authoring is unavailable; fpkg rebuild supports only validated source-backed GD profiles",
    "new-license and new-keystone generation material/provenance remains gated",
    "NP/trophy generation, custom PlayGo, updates and unknown container records remain unsupported",
    "console installation/launch and save compatibility are unverified",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Application,
    ParamSfo,
    ContainerMetadata,
    Keystone,
    NpTrophy,
    PlayGo,
    /// Unclassified sce_sys files must not silently become ordinary PFS files.
    UnclassifiedSystem,
}

#[derive(Debug)]
pub struct Resource {
    pub source: SourceReference,
    pub size: u64,
    pub kind: ResourceKind,
}

#[derive(Debug)]
pub struct Inventory {
    pub identity: Identity,
    pub resources: Vec<Resource>,
    pub directory_count: usize,
    pub source_bytes: u64,
    /// Input-specific limitations, separate from the global writer gates.
    pub input_blockers: Vec<String>,
}

fn classify(path: &str) -> ResourceKind {
    match path {
        "sce_sys/param.sfo" => ResourceKind::ParamSfo,
        "sce_sys/keystone" => ResourceKind::Keystone,
        p if container_id(p).is_some() => ResourceKind::ContainerMetadata,
        "sce_sys/nptitle.dat" | "sce_sys/npbind.dat" => ResourceKind::NpTrophy,
        p if p.starts_with("sce_sys/trophy/") => ResourceKind::NpTrophy,
        p if p.starts_with("sce_sys/playgo-") || p.starts_with("sce_sys/app/") => {
            ResourceKind::PlayGo
        }
        p if p.starts_with("sce_sys/") => ResourceKind::UnclassifiedSystem,
        _ => ResourceKind::Application,
    }
}

pub(crate) fn container_id(path: &str) -> Option<u32> {
    match path {
        "sce_sys/param.sfo" => Some(0x1000),
        "sce_sys/pic1.png" => Some(0x1006),
        "sce_sys/icon0.png" => Some(0x1200),
        "sce_sys/pic0.png" => Some(0x1220),
        "sce_sys/snd0.at9" => Some(0x1240),
        _ => None,
    }
}

/// Inventory a supported standalone GP4 under one explicitly approved source root.
///
/// Reports input blockers rather than treating arbitrary application trees as
/// rebuild-ready. Existing keystones are never replaced; their size alone is not
/// authentication. Missing keystones require a future explicit homebrew-generation
/// policy, not an implicit replacement for existing-title save identity.
///
/// Reads only bounded SFO metadata; no payload reads, scratch or output. Cancellation
/// is checked before GP4 preflight and between inventory entries; bounded existing
/// GP4 preflight itself is not interruptible. Memory scales with GP4's capped entry
/// count. Sources must remain stable: this is not a concurrent-mutation sandbox or
/// an input snapshot that a future writer may trust for later I/O.
pub fn preflight(
    project: &Project,
    approved_root: &Path,
    mut cancelled: impl FnMut() -> bool,
) -> io::Result<Inventory> {
    let mut check_cancel = || {
        if cancelled() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "authoring preflight cancelled",
            ))
        } else {
            Ok(())
        }
    };
    check_cancel()?;
    let approved = project.preflight(approved_root)?;
    let mut inventory = Inventory {
        identity: approved.identity,
        resources: Vec::with_capacity(approved.sources.len()),
        directory_count: project.directories().len(),
        source_bytes: 0,
        input_blockers: Vec::new(),
    };
    let mut keystone = false;
    for source in approved.sources {
        check_cancel()?;
        let metadata = fs::symlink_metadata(&source.resolved)?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source changed or is not a regular file",
            ));
        }
        let size = metadata.len();
        inventory.source_bytes = inventory.source_bytes.checked_add(size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "source byte total overflow")
        })?;
        let kind = classify(&source.target);
        let blocker = match kind {
            ResourceKind::Keystone => {
                keystone = true;
                (size != KEYSTONE_SIZE).then_some("keystone must contain exactly 96 bytes; never regenerate an existing-title keystone")
            }
            ResourceKind::NpTrophy => {
                Some("NP/trophy authoring placement and identity validation are not established")
            }
            ResourceKind::PlayGo => Some(
                "supplied PlayGo scheduling/layout cannot be copied; regeneration is not implemented",
            ),
            ResourceKind::UnclassifiedSystem => {
                Some("system resource authoring placement/preservation is not classified")
            }
            _ => None,
        };
        if let Some(reason) = blocker {
            inventory
                .input_blockers
                .push(format!("{}: {reason}", source.target));
        }
        inventory.resources.push(Resource { source, size, kind });
    }
    if !keystone {
        inventory.input_blockers.push(
            "missing sce_sys/keystone: existing-title rebuild requires its original; new homebrew generation needs an explicit reviewed policy".into(),
        );
    }
    check_cancel()?;
    Ok(inventory)
}

/// Allocation ceiling for one authoring record, regardless of caller's limit.
pub const MAX_RECORD_SIZE: u32 = 16 * 1024 * 1024;
const RAW_HEADER_SIZE: usize = 0x1100;
const RECORD_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordRole {
    /// Layout/identity-dependent artifacts must be regenerated, never copied.
    Generated,
    NpResource,
    ApplicationMetadata,
    /// Unknown records remain visible and block rebuilding.
    Unclassified,
}

fn record_role(id: u32) -> RecordRole {
    match id {
        0x402 | 0x403 => RecordRole::NpResource,
        0x1
        | 0x10
        | 0x20
        | 0x80
        | 0x100
        | 0x200
        | 0x400
        | 0x401
        | 0x409
        | 0x1001..=0x1003
        | 0x1008..=0x100a => RecordRole::Generated,
        _ if extract::metadata_name(id).is_some() => RecordRole::ApplicationMetadata,
        _ => RecordRole::Unclassified,
    }
}

#[derive(Debug)]
pub struct ContainerRecord {
    pub entry: Entry,
    pub role: RecordRole,
}

/// Sensitive local inventory. Deliberately no Debug: header/digest/NP bytes must
/// not become accidental logs or public fixture fingerprints. No key records retained.
pub struct PackageInventory {
    pub records: Vec<ContainerRecord>,
    pub application_files: usize,
    pub keystone_size: Option<u64>,
    pub input_blockers: Vec<String>,
    raw_header: [u8; RAW_HEADER_SIZE],
    general_digests: Option<Vec<u8>>,
    np_resources: Vec<(u32, Vec<u8>)>,
    keystone: Option<Vec<u8>>,
}

impl PackageInventory {
    /// Original complete header, including unknown fields, digests and signature.
    /// Retention is not integrity verification or permission to copy into output.
    pub fn raw_header(&self) -> &[u8] {
        &self.raw_header
    }
    pub fn general_digests(&self) -> Option<&[u8]> {
        self.general_digests.as_deref()
    }
    /// Original decoded NP container resource, outside the extraction namespace.
    pub fn np_resource(&self, id: u32) -> Option<&[u8]> {
        self.np_resources
            .iter()
            .find(|(key, _)| *key == id)
            .map(|(_, bytes)| bytes.as_slice())
    }
    /// Original 96-byte keystone, not authenticated and never regenerated.
    pub fn keystone(&self) -> Option<&[u8]> {
        self.keystone.as_deref()
    }
}

impl<R: Read + Seek> ReadAt for Package<R> {
    fn len(&self) -> u64 {
        self.header.package_size
    }
    fn read_at(&mut self, offset: u64, data: &mut [u8]) -> Result<(), Error> {
        crate::range(offset, data.len() as u64, self.header.package_size)?;
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(data)?;
        Ok(())
    }
}

impl<R: Read + Seek> Package<R> {
    /// Read a container record for authoring, capped before allocation. This is not
    /// an application path or authentication API. Only existing public DK3 recovery
    /// is supported; key index 2 is never silently decrypted with key 3.
    /// Cancellation is checked before I/O and between 64 KiB chunks. Keep source
    /// stable; callers must revalidate inputs during any future multi-pass build.
    pub fn read_authoring_record(
        &mut self,
        id: u32,
        limit: u32,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<Option<Vec<u8>>, Error> {
        check_cancel(&mut cancelled)?;
        let Some(entry) = self.entries.iter().find(|e| e.id == id).cloned() else {
            return Ok(None);
        };
        if entry.size > limit.min(MAX_RECORD_SIZE) {
            return Err(Error::LimitExceeded("authoring container record size"));
        }
        let mut dk3 = [0; 32];
        if entry.encrypted() {
            if entry.key_index() != 3 {
                return Err(Error::DecryptionUnavailable {
                    entry_id: id,
                    key_index: entry.key_index(),
                });
            }
            if entry.flags1 & 0x1000_0000 != 0 {
                return Err(Error::Unsupported("new container encryption algorithm"));
            }
            let keys = self
                .entries
                .iter()
                .find(|e| e.id == 0x10)
                .cloned()
                .ok_or(Error::KeyRecoveryFailed)?;
            if keys.encrypted() || keys.size != 2048 {
                return Err(Error::Malformed("fake-key entry layout"));
            }
            let mut bytes = [0; 2048];
            self.read_at(u64::from(keys.offset), &mut bytes)?;
            dk3 = crypto::recover_dk3(&bytes)?;
        }
        let mut bytes = vec![0; entry.size as usize];
        for (index, chunk) in bytes.chunks_mut(RECORD_CHUNK_SIZE).enumerate() {
            check_cancel(&mut cancelled)?;
            extract::read_container(
                self,
                &entry,
                &dk3,
                (index * RECORD_CHUNK_SIZE) as u64,
                chunk,
            )?;
        }
        check_cancel(&mut cancelled)?;
        Ok(Some(bytes))
    }
}

fn check_cancel(cancelled: &mut impl FnMut() -> bool) -> Result<(), Error> {
    if cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// Inventory a supported fake GD package without changing extraction semantics.
/// Retains header, bounded general digests and NP records; enumerates the decoded
/// application tree to locate its original keystone. Unknown records and missing
/// resources remain blockers. Unsupported encrypted retained records fail explicitly.
/// Existing bounded open_game preparation is not interruptible; cancellation is
/// checked immediately before/after it. No payload hashes, edits or output occur.
pub fn preflight_package<R: Read + Seek>(
    mut package: Package<R>,
    mut cancelled: impl FnMut() -> bool,
) -> Result<PackageInventory, Error> {
    check_cancel(&mut cancelled)?;
    let mut raw_header = [0; RAW_HEADER_SIZE];
    package.read_at(0, &mut raw_header)?;
    let records: Vec<_> = package
        .entries
        .iter()
        .map(|entry| ContainerRecord {
            entry: entry.clone(),
            role: record_role(entry.id),
        })
        .collect();
    let mut input_blockers = Vec::new();
    for record in &records {
        check_cancel(&mut cancelled)?;
        if record.role == RecordRole::Unclassified {
            input_blockers.push(format!(
                "unclassified container record {:#x}: preservation/regeneration is not established",
                record.entry.id
            ));
        }
    }
    let general_digests = package.read_authoring_record(0x80, MAX_RECORD_SIZE, &mut cancelled)?;
    if general_digests.is_none() {
        input_blockers.push("missing general digests record".into());
    }
    let mut np_resources = Vec::new();
    for id in [0x402, 0x403] {
        if let Some(bytes) = package.read_authoring_record(id, MAX_RECORD_SIZE, &mut cancelled)? {
            np_resources.push((id, bytes));
            input_blockers.push(format!(
                "NP resource {id:#x}: authoring placement/identity validation is not established"
            ));
        }
    }
    check_cancel(&mut cancelled)?;
    let mut game = package.open_game()?;
    check_cancel(&mut cancelled)?;
    let mut keystone_size = None;
    let mut application_files = 0;
    for entry in game.entries() {
        check_cancel(&mut cancelled)?;
        if entry.kind() != FileKind::File {
            continue;
        }
        application_files += 1;
        if entry.path() == "sce_sys/keystone" {
            keystone_size = Some(entry.size());
        }
        if matches!(
            classify(entry.path()),
            ResourceKind::NpTrophy | ResourceKind::PlayGo | ResourceKind::UnclassifiedSystem
        ) {
            input_blockers.push(format!(
                "{}: authoring placement/regeneration is not established",
                entry.path()
            ));
        }
    }
    if keystone_size != Some(KEYSTONE_SIZE) {
        input_blockers.push("missing or wrong-size original sce_sys/keystone; never regenerate existing-title save identity".into());
    }
    let keystone = if keystone_size == Some(KEYSTONE_SIZE) {
        let index = game
            .entries()
            .iter()
            .position(|e| e.path() == "sce_sys/keystone")
            .ok_or(Error::Malformed("keystone inventory changed"))?;
        check_cancel(&mut cancelled)?;
        let mut bytes = vec![0; KEYSTONE_SIZE as usize];
        game.read_entry(index)?.read_exact(&mut bytes)?;
        check_cancel(&mut cancelled)?;
        Some(bytes)
    } else {
        None
    };
    Ok(PackageInventory {
        records,
        application_files,
        keystone_size,
        input_blockers,
        raw_header,
        general_digests,
        np_resources,
        keystone,
    })
}
