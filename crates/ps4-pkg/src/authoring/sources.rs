//! Narrow GP4-to-image pipeline. No container records or generated resources.

use crate::{
    gp4,
    inner_image::{Entry, InnerImage},
};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const BUFFER: usize = 64 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check(cancelled: &mut impl FnMut() -> bool) -> io::Result<()> {
    if cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "GP4 image build cancelled",
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Inner,
    Container(u32),
}

/// Public placement/size only: snapshot fingerprints are deliberately private.
pub struct PreparedResource {
    pub target: String,
    pub size: u64,
    pub placement: Placement,
    relative: PathBuf,
    stamp: Stamp,
    digest: [u8; 32],
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

fn placement(path: &str) -> io::Result<Placement> {
    // Deliberately smaller than extraction's map: no NP/trophy, generated or
    // unreviewed system resources silently fall through to ordinary PFS files.
    if let Some(id) = super::container_id(path) {
        return Ok(Placement::Container(id));
    }
    match path {
        "sce_sys/keystone" => Ok(Placement::Inner),
        p if p.starts_with("sce_sys/") => Err(invalid(
            "unsupported system resource: NP/trophy, PlayGo and unclassified placement remain gated",
        )),
        _ => Ok(Placement::Inner),
    }
}

/// Stable-source plan for one standalone-app GP4. Unix descriptor-relative input
/// opens reject symlinks/special files. Payload buffers are 64 KiB (SFO metadata
/// additionally uses its existing 16 MiB cap); path
/// metadata scales with GP4's existing cap. No keys/passcode/fingerprints in Debug.
///
/// This detects ordinary changes, not malicious writes that restore all metadata.
/// Keep sources and output parents stable; no filesystem snapshot is created.
pub struct PreparedProject {
    root: pkg_fs::SourceRoot,
    root_path: PathBuf,
    identity: gp4::Identity,
    resources: Vec<PreparedResource>,
    inner_indices: Vec<usize>,
    image: InnerImage,
    source_bytes: u64,
}

impl PreparedProject {
    /// Hash approved sources, validate their exact SFO bytes and plan resource
    /// placement. Requires original 96-byte keystone, never generates/replaces it.
    /// Images do not authenticate keystones, validate artwork or establish saves.
    pub fn new(
        project: &gp4::Project,
        approved_root: &Path,
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<Self> {
        check(&mut cancelled)?;
        project.validate()?;
        // Check original traversal too, before lexical normalization removes `..`.
        gp4::no_symlinks(approved_root)?;
        let root_path = gp4::absolute(approved_root)?;
        let sources = project.source_references()?;
        if sources
            .iter()
            .any(|source| !source.resolved.starts_with(&root_path))
        {
            return Err(invalid("source outside explicitly approved root"));
        }
        project.check_source_traversal()?;
        let root = pkg_fs::SourceRoot::open(&root_path)?;
        let mut resources = Vec::new();
        let mut identity = None;
        let mut source_bytes = 0u64;
        let mut keystone = false;
        for source in sources {
            check(&mut cancelled)?;
            let relative = source
                .resolved
                .strip_prefix(&root_path)
                .map_err(|_| invalid("source outside explicitly approved root"))?
                .to_path_buf();
            let place = placement(&source.target)
                .map_err(|e| invalid(&format!("{}: {e}", source.target)))?;
            let mut file = root.open_file(&relative)?;
            let metadata = file.metadata()?;
            if source.target == "sce_sys/keystone" {
                if metadata.len() != super::KEYSTONE_SIZE {
                    return Err(invalid(
                        "original sce_sys/keystone must contain exactly 96 bytes; never regenerate existing-title save identity",
                    ));
                }
                keystone = true;
            }
            let is_sfo = source.target == "sce_sys/param.sfo";
            if is_sfo && metadata.len() > psf::MAX_SIZE as u64 {
                return Err(invalid("SFO size limit"));
            }
            let before = stamp(&metadata);
            let mut sfo = Vec::new();
            let digest = hash(&mut file, metadata.len(), &mut cancelled, |bytes| {
                if is_sfo {
                    sfo.extend_from_slice(bytes);
                }
                Ok(())
            })?;
            if before != stamp(&file.metadata()?) {
                return Err(invalid("source changed while preparing image"));
            }
            if is_sfo {
                let found = gp4::sfo_identity(&sfo)?;
                if found.content_id != project.content_id() {
                    return Err(invalid("GP4 content_id disagrees with SFO"));
                }
                identity = Some(found);
            }
            source_bytes = source_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| invalid("source byte total overflow"))?;
            resources.push(PreparedResource {
                target: source.target,
                size: metadata.len(),
                placement: place,
                relative,
                stamp: before,
                digest,
            });
        }
        if !keystone {
            return Err(invalid(
                "missing original sce_sys/keystone; homebrew keystone generation remains gated",
            ));
        }
        // Entries share resource indices, with directories appended after files.
        let mut entries: Vec<_> = resources
            .iter()
            .map(|r| Entry {
                path: r.target.clone(),
                size: Some(r.size),
            })
            .collect();
        entries.extend(project.directories().iter().map(|p| Entry {
            path: p.clone(),
            size: None,
        }));
        // Keep resource indices stable for callbacks, filtering via an explicit map.
        let inner_indices: Vec<_> = resources
            .iter()
            .enumerate()
            .filter(|(_, r)| r.placement == Placement::Inner)
            .map(|(i, _)| i)
            .chain(resources.len()..entries.len())
            .collect();
        let inner_entries: Vec<_> = inner_indices.iter().map(|&i| entries[i].clone()).collect();
        let image = InnerImage::new(
            &inner_entries,
            unix_timestamp(&project.settings().timestamp),
        )?;
        // Store precisely the callback-indexed namespace, not excluded metadata.
        let result = Self {
            root,
            root_path,
            identity: identity.ok_or_else(|| invalid("missing SFO"))?,
            resources,
            inner_indices,
            image,
            source_bytes,
        };
        result.verify(&mut cancelled)?;
        Ok(result)
    }

    pub fn identity(&self) -> &gp4::Identity {
        &self.identity
    }
    pub fn resources(&self) -> &[PreparedResource] {
        &self.resources
    }
    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }
    pub fn pfs_size(&self) -> u64 {
        self.image.pfs_size()
    }
    pub fn pfsc_size(&self) -> u64 {
        self.image.pfsc_size()
    }

    fn open(&self, resource: &PreparedResource) -> io::Result<File> {
        let file = self.root.open_file(&resource.relative)?;
        if stamp(&file.metadata()?) != resource.stamp {
            return Err(invalid("source changed since image preparation"));
        }
        Ok(file)
    }

    fn verify(&self, cancelled: &mut impl FnMut() -> bool) -> io::Result<()> {
        for resource in &self.resources {
            check(cancelled)?;
            let mut file = self.open(resource)?;
            if hash(&mut file, resource.size, cancelled, |_| Ok(()))? != resource.digest
                || stamp(&file.metadata()?) != resource.stamp
            {
                return Err(invalid("source changed since image preparation"));
            }
        }
        check(cancelled)
    }

    /// Stream one prepared resource verbatim for future container assembly.
    /// On failure discard partial output. Revalidates size, identity and SHA-256.
    pub fn copy_resource(
        &self,
        index: usize,
        output: &mut impl Write,
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        check(&mut cancelled)?;
        let resource = self
            .resources
            .get(index)
            .ok_or_else(|| invalid("invalid resource index"))?;
        let mut file = self.open(resource)?;
        let digest = hash(&mut file, resource.size, &mut cancelled, |bytes| {
            output.write_all(bytes)
        })?;
        if digest != resource.digest || stamp(&file.metadata()?) != resource.stamp {
            return Err(invalid("source changed while copying resource"));
        }
        check(&mut cancelled)
    }

    /// Write only inner application files/directories. Container resources are
    /// excluded, not discarded from this plan. Rehash ALL sources (even excluded
    /// metadata/empty files) before publication; scratch cleans on any failure.
    /// Output must be outside approved root; existing outputs are never replaced.
    /// Requires one image's scratch disk space plus unchanged source files.
    pub fn write_inner_new(
        &self,
        destination: &Path,
        cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        self.write_image_new(destination, None, cancelled)
    }

    /// Write signed/encrypted outer `.pfs` containing the prepared raw PFSC.
    /// Requires an explicit already-derived image key, not the GP4 passcode.
    /// Container resources remain excluded; this is not a PKG or complete game.
    /// Same stable-source, cancellation and publication rules as write_inner_new.
    pub fn write_outer_new(
        &self,
        destination: &Path,
        image_key: &[u8; 32],
        cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        self.write_image_new(destination, Some(image_key), cancelled)
    }

    /// Exact outer-image bytes; filesystem overhead is additional.
    pub fn outer_pfs_size(&self) -> io::Result<u64> {
        Ok(crate::outer_image::OuterImage::new(&self.image, self.image.timestamp())?.pfs_size())
    }

    fn write_image_new(
        &self,
        destination: &Path,
        image_key: Option<&[u8; 32]>,
        cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        let destination = gp4::absolute(destination)?;
        if destination.starts_with(&self.root_path) {
            return Err(invalid("image output must be outside source root"));
        }
        let cancelled = RefCell::new(cancelled);
        let mut cancel = || (cancelled.borrow_mut())();
        self.verify(&mut cancel)?;
        let mut active: Option<(usize, File, Sha256)> = None;
        let read = |index: usize, offset, bytes: &mut [u8]| {
            let resource = &self.resources[self.inner_indices[index]];
            if offset == 0 {
                active = Some((index, self.open(resource)?, Sha256::new()));
            }
            let (current, file, digest) = active
                .as_mut()
                .ok_or_else(|| invalid("image source stream order"))?;
            if *current != index {
                return Err(invalid("image source stream order"));
            }
            file.read_exact(bytes)?;
            digest.update(&*bytes);
            if stamp(&file.metadata()?) != resource.stamp {
                return Err(invalid("source changed while streaming image"));
            }
            if offset + bytes.len() as u64 == resource.size
                && <[u8; 32]>::from(std::mem::take(digest).finalize()) != resource.digest
            {
                return Err(invalid("source digest changed while streaming image"));
            }
            Ok(())
        };
        let cancel = || (cancelled.borrow_mut())();
        let verify = || self.verify(&mut || (cancelled.borrow_mut())());
        if let Some(key) = image_key {
            crate::outer_image::OuterImage::new(&self.image, self.image.timestamp())?
                .write_new_checked(&destination, key, read, cancel, verify)
        } else {
            self.image
                .write_new_checked(&destination, read, cancel, verify)
        }
    }
}

fn hash(
    file: &mut File,
    size: u64,
    cancelled: &mut impl FnMut() -> bool,
    mut consume: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = [0; BUFFER];
    let mut left = size;
    while left != 0 {
        check(cancelled)?;
        let n = left.min(BUFFER as u64) as usize;
        file.read_exact(&mut buffer[..n])?;
        digest.update(&buffer[..n]);
        consume(&buffer[..n])?;
        left -= n as u64;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(invalid("source grew while reading"));
    }
    check(cancelled)?;
    Ok(digest.finalize().into())
}

fn unix_timestamp(value: &str) -> i64 {
    // Project validation already checked Gregorian date/time, years 0001..9999.
    let n = |a, b| {
        value.as_bytes()[a..b]
            .iter()
            .fold(0i64, |n, b| n * 10 + i64::from(b - b'0'))
    };
    let year = n(0, 4);
    let leap = |y| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_before = |y: i64| {
        let y = y - 1;
        365 * y + y / 4 - y / 100 + y / 400
    };
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let days = days_before(year) - days_before(1970)
        + months[..(n(5, 7) - 1) as usize].iter().sum::<i64>()
        + n(8, 10)
        - 1;
    days * 86400 + n(11, 13) * 3600 + n(14, 16) * 60 + n(17, 19)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_timestamp_has_no_host_timezone_or_dst() {
        assert_eq!(unix_timestamp("1970-01-01 00:00:00"), 0);
        assert_eq!(unix_timestamp("1969-12-31 23:59:59"), -1);
        assert_eq!(unix_timestamp("2000-03-01 00:00:00"), 951868800);
        assert_eq!(unix_timestamp("2026-10-31 12:34:56"), 1793450096);
    }

    #[test]
    fn supported_container_placements_agree_with_existing_named_resource_map() {
        for (name, id) in [
            ("param.sfo", 0x1000),
            ("pic1.png", 0x1006),
            ("icon0.png", 0x1200),
            ("pic0.png", 0x1220),
            ("snd0.at9", 0x1240),
        ] {
            assert_eq!(
                placement(&format!("sce_sys/{name}")).unwrap(),
                Placement::Container(id)
            );
            assert_eq!(crate::extract::metadata_name(id).as_deref(), Some(name));
        }
    }
}
