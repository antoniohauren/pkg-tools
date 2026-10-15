use crate::{Error, FileKind, Package, Rap, npdrm};
use sha1::{Digest, Sha1};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static SERIAL: AtomicU64 = AtomicU64::new(0);

/// Liberate an extracted game tree into a new PKG. The source must remain unchanged.
pub fn liberate_folder_with_progress(
    source: &Path,
    content_id: [u8; 48],
    rap: &Rap,
    destination: &Path,
    cancel: impl Fn() -> bool,
    progress: impl FnMut(u64, u64),
) -> Result<(), Error> {
    folder_source(source, content_id, &cancel)?.liberate(rap, destination, false, cancel, progress)
}

/// Liberate an extracted game tree into a new folder, leaving the source unchanged.
pub fn liberate_folder_to_directory_with_progress(
    source: &Path,
    content_id: [u8; 48],
    rap: &Rap,
    destination: &Path,
    cancel: impl Fn() -> bool,
    progress: impl FnMut(u64, u64),
) -> Result<(), Error> {
    folder_source(source, content_id, &cancel)?.liberate(rap, destination, true, cancel, progress)
}

fn folder_source(
    source: &Path,
    content_id: [u8; 48],
    cancel: &impl Fn() -> bool,
) -> Result<FolderSource, Error> {
    let mut tree = BTreeMap::new();
    let mut bytes = 0;
    let mut pending = vec![String::new()];
    if !fs::symlink_metadata(source)?.is_dir() {
        return Err(Error::Unsupported("source must be a real directory"));
    }
    while let Some(parent) = pending.pop() {
        cancelled(&cancel)?;
        for item in fs::read_dir(source.join(&parent))? {
            cancelled(&cancel)?;
            let item = item?;
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| Error::Unsupported("non-UTF-8 path"))?;
            let path = if parent.is_empty() {
                name.clone()
            } else {
                format!("{parent}/{name}")
            };
            if !pkg_fs::valid_component(&name) || name.eq_ignore_ascii_case(pkg_fs::MARKER) {
                return Err(Error::UnsafePath(path));
            }
            if path.len() > 4096 || path.split('/').count() > 128 {
                return Err(Error::LimitExceeded("path depth/length"));
            }
            let metadata = fs::symlink_metadata(item.path())?;
            if !metadata.is_dir() && !metadata.is_file() {
                return Err(Error::UnsafePath(path));
            }
            // Nearby licenses are inputs, not game payloads to publish in the PKG.
            if metadata.is_file() && name.to_ascii_lowercase().ends_with(".rap") {
                continue;
            }
            let flags = if metadata.is_dir() {
                4
            } else {
                let mut magic = [0; 4];
                let mut file = File::open(item.path())?;
                if metadata.len() >= 4 {
                    file.read_exact(&mut magic)?;
                }
                match &magic {
                    b"SCE\0" => 1,
                    b"NPD\0" => {
                        let mut header = [0; 0x84];
                        header[..4].copy_from_slice(&magic);
                        file.read_exact(&mut header[4..])?;
                        if crate::be32(&header, 0x80) & 0x01000000 != 0 {
                            9
                        } else {
                            2
                        }
                    }
                    _ => 3,
                }
            };
            if metadata.is_dir() {
                pending.push(path.clone());
            }
            Package::<File>::insert(
                &mut tree,
                crate::FileEntry {
                    path,
                    offset: 0,
                    size: if metadata.is_dir() { 0 } else { metadata.len() },
                    flags,
                },
                &mut bytes,
                false,
            )?;
        }
    }
    Ok(FolderSource {
        root: source.to_path_buf(),
        entries: tree.into_values().collect(),
        content_id,
        metadata: vec![
            crate::Metadata {
                id: 1,
                data: 3u32.to_be_bytes().to_vec(),
            },
            crate::Metadata {
                id: 2,
                data: 5u32.to_be_bytes().to_vec(),
            },
            crate::Metadata {
                id: 3,
                data: 0x4eu32.to_be_bytes().to_vec(),
            },
            crate::Metadata {
                id: 4,
                data: vec![0; 8],
            },
        ],
    })
}

struct FolderSource {
    root: PathBuf,
    entries: Vec<crate::FileEntry>,
    metadata: Vec<crate::Metadata>,
    content_id: [u8; 48],
}
impl LiberationSource for FolderSource {
    fn entries(&self) -> &[crate::FileEntry] {
        &self.entries
    }
    fn metadata(&self) -> &[crate::Metadata] {
        &self.metadata
    }
    fn content_id(&self) -> [u8; 48] {
        self.content_id
    }
    fn read_entry(&mut self, index: usize) -> Result<Box<dyn Read + '_>, Error> {
        let entry = &self.entries[index];
        let path = self.root.join(entry.path());
        if !fs::symlink_metadata(&path)?.is_file() {
            return Err(Error::UnsafePath(entry.path().into()));
        }
        let file = File::open(path)?;
        if file.metadata()?.len() != entry.size() {
            return Err(Error::Malformed("source changed"));
        }
        Ok(Box::new(file.take(entry.size())))
    }
}
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn cancelled(cancel: &impl Fn() -> bool) -> Result<(), Error> {
    if cancel() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_be_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_be_bytes());
}
fn aligned(n: u64) -> Result<u64, Error> {
    n.checked_add(15)
        .map(|n| n & !15)
        .ok_or(Error::LimitExceeded("output size"))
}
fn debug_crypt(qa: &[u8; 16], offset: u64, bytes: &mut [u8]) {
    assert!(offset.is_multiple_of(16));
    let mut seed = [0; 64];
    seed[..8].copy_from_slice(&qa[..8]);
    seed[8..16].copy_from_slice(&qa[..8]);
    seed[16..24].copy_from_slice(&qa[8..]);
    seed[24..32].copy_from_slice(&qa[8..]);
    for (i, part) in bytes.chunks_mut(16).enumerate() {
        seed[56..].copy_from_slice(&(offset / 16 + i as u64).to_be_bytes());
        for (b, k) in part.iter_mut().zip(Sha1::digest(seed)) {
            *b ^= k;
        }
    }
}

impl<R: Read + Seek> Package<R> {
    pub fn liberate_with_progress(
        &mut self,
        rap: &Rap,
        destination: impl AsRef<Path>,
        cancel: impl Fn() -> bool,
        progress: impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        LiberationSource::liberate(self, rap, destination, false, cancel, progress)
    }

    /// Write liberated payloads directly into a new folder, without repacking a PKG.
    pub fn liberate_to_directory_with_progress(
        &mut self,
        rap: &Rap,
        destination: impl AsRef<Path>,
        cancel: impl Fn() -> bool,
        progress: impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        LiberationSource::liberate(self, rap, destination, true, cancel, progress)
    }
}

trait LiberationSource {
    fn entries(&self) -> &[crate::FileEntry];
    fn metadata(&self) -> &[crate::Metadata];
    fn content_id(&self) -> [u8; 48];
    fn read_entry(&mut self, index: usize) -> Result<Box<dyn Read + '_>, Error>;

    /// Convert supported local-license NPDRM payloads to free-license payloads
    /// and write a new folder or debug PKG. Sources and existing outputs are never replaced.
    /// Preparation is bounded to 256 MiB each of transformed files and decoded SELF
    /// sections. Progress measures output bytes after preparation.
    fn liberate(
        &mut self,
        rap: &Rap,
        destination: impl AsRef<Path>,
        directory: bool,
        cancel: impl Fn() -> bool,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        cancelled(&cancel)?;
        let destination = destination.as_ref();
        match fs::symlink_metadata(destination) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "destination exists",
                )
                .into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if !self
            .metadata()
            .iter()
            .any(|m| m.id == 2 && m.data == 5u32.to_be_bytes())
        {
            return Err(Error::Unsupported(
                "liberation requires a PS3 game-executable package",
            ));
        }
        let cid = self.content_id();
        let mut replacements = BTreeMap::<usize, Vec<u8>>::new();
        let mut edats = Vec::new();
        let mut sections = Vec::new();
        let mut replacement_size = 0u64;
        let mut section_size = 0u64;
        for index in 0..self.entries().len() {
            cancelled(&cancel)?;
            if self.entries()[index].kind() == FileKind::Directory
                || self.entries()[index].size() < 4
            {
                continue;
            }
            let mut magic = [0; 4];
            self.read_entry(index)?.read_exact(&mut magic)?;
            if magic == *b"NPD\0" {
                let mut header = [0; 0x90];
                self.read_entry(index)?.read_exact(&mut header)?;
                if crate::be32(&header, 0x80) & 0x01000000 != 0 || crate::be32(&header, 8) == 3 {
                    continue;
                }
                edats.push(index);
                continue;
            }
            if magic != *b"SCE\0" {
                continue;
            }
            let mut b = self.conversion_file(index, &cancel)?;
            let name = self.entries()[index].path().rsplit('/').next().unwrap();
            let decoded =
                npdrm::convert_self(&mut b, rap, &cid, name, &cancel).map_err(|source| {
                    Error::ConversionFile {
                        path: self.entries()[index].path().into(),
                        source: Box::new(source),
                    }
                })?;
            if decoded.is_empty() {
                continue;
            }
            section_size += decoded.iter().map(|s| s.len() as u64).sum::<u64>();
            replacement_size += b.len() as u64;
            if section_size > npdrm::MAX_FILE || replacement_size > npdrm::MAX_FILE {
                return Err(Error::LimitExceeded("liberation working set"));
            }
            sections.extend(decoded);
            replacements.insert(index, b);
        }
        for index in edats {
            cancelled(&cancel)?;
            let b = self.conversion_file(index, &cancel)?;
            let name = self.entries()[index].path().rsplit('/').next().unwrap();
            if let Some(out) = npdrm::convert_edat(&b, rap, &cid, name, &sections, &cancel)
                .map_err(|source| Error::ConversionFile {
                    path: self.entries()[index].path().into(),
                    source: Box::new(source),
                })?
            {
                replacement_size += out.len() as u64;
                if replacement_size > npdrm::MAX_FILE {
                    return Err(Error::LimitExceeded("liberation working set"));
                }
                replacements.insert(index, out);
            }
        }
        if replacements.is_empty() {
            return Err(Error::Unsupported(
                "no convertible local-license SELF/EDAT payloads",
            ));
        }
        drop(sections);
        if directory {
            self.write_directory(destination, &replacements, &cancel, &mut progress)
        } else {
            self.write_liberated(destination, &replacements, &cancel, &mut progress)
        }
    }

    fn write_directory(
        &mut self,
        destination: &Path,
        replacements: &BTreeMap<usize, Vec<u8>>,
        cancel: &impl Fn() -> bool,
        progress: &mut impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        #[cfg(not(unix))]
        {
            let _ = (destination, replacements, cancel, progress);
            Err(Error::Unsupported(
                "safe disk extraction currently requires Unix",
            ))
        }
        #[cfg(unix)]
        {
            cancelled(cancel)?;
            let total = self
                .entries()
                .iter()
                .enumerate()
                .try_fold(0u64, |sum, (i, e)| {
                    sum.checked_add(replacements.get(&i).map_or(e.size(), |b| b.len() as u64))
                        .ok_or(Error::LimitExceeded("total liberated size"))
                })?;
            let output = pkg_fs::Output::create(destination)?;
            let result = (|| {
                output.mark_incomplete()?;
                let mut completed = 0;
                let mut buffer = [0; 65536];
                progress(0, total);
                for index in 0..self.entries().len() {
                    cancelled(cancel)?;
                    let entry = &self.entries()[index];
                    if entry.kind() == FileKind::Directory {
                        output.create_directory(entry.path())?;
                        continue;
                    }
                    let mut file = output.create_file(entry.path())?;
                    let size = replacements
                        .get(&index)
                        .map_or(entry.size(), |b| b.len() as u64);
                    let mut reader: Box<dyn Read + '_> = match replacements.get(&index) {
                        Some(bytes) => Box::new(bytes.as_slice()),
                        None => self.read_entry(index)?,
                    };
                    let mut remaining = size;
                    while remaining != 0 {
                        cancelled(cancel)?;
                        let n = remaining.min(buffer.len() as u64) as usize;
                        reader.read_exact(&mut buffer[..n])?;
                        file.write_all(&buffer[..n])?;
                        remaining -= n as u64;
                        completed += n as u64;
                        progress(completed, total);
                    }
                    file.flush()?;
                }
                cancelled(cancel)?;
                output.finish()?;
                Ok(())
            })();
            result.map_err(|source| Error::IncompleteExtraction {
                path: destination.to_owned(),
                source: Box::new(source),
            })
        }
    }
    fn conversion_file(
        &mut self,
        index: usize,
        cancel: &impl Fn() -> bool,
    ) -> Result<Vec<u8>, Error> {
        if self.entries()[index].size() > npdrm::MAX_FILE {
            return Err(Error::LimitExceeded("SELF/EDAT conversion file (256 MiB)"));
        }
        let mut b = Vec::new();
        let mut reader = self.read_entry(index)?;
        let mut buffer = [0; 65536];
        loop {
            cancelled(cancel)?;
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            b.extend_from_slice(&buffer[..n]);
        }
        Ok(b)
    }
    fn write_liberated(
        &mut self,
        destination: &Path,
        replacements: &BTreeMap<usize, Vec<u8>>,
        cancel: &impl Fn() -> bool,
        progress: &mut impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        let count = self.entries().len();
        let mut table = vec![0; count * 32];
        let mut names = Vec::new();
        let mut sizes = Vec::with_capacity(count);
        for (i, e) in self.entries().iter().enumerate() {
            let name_offset = table.len() + names.len();
            put32(
                &mut table,
                i * 32,
                u32::try_from(name_offset).map_err(|_| Error::LimitExceeded("PKG name offset"))?,
            );
            put32(&mut table, i * 32 + 4, e.path().len() as u32);
            names.extend_from_slice(e.path().as_bytes());
            names.resize(aligned(names.len() as u64)? as usize, 0);
            let size = replacements.get(&i).map_or(e.size(), |b| b.len() as u64);
            put64(&mut table, i * 32 + 16, size);
            put32(&mut table, i * 32 + 24, e.flags());
            sizes.push(size);
        }
        let mut data_size = (table.len() + names.len()) as u64;
        for (i, size) in sizes.iter().enumerate() {
            put64(&mut table, i * 32 + 8, data_size);
            data_size = data_size
                .checked_add(aligned(*size)?)
                .ok_or(Error::LimitExceeded("PKG size"))?;
        }
        table.extend(names);
        let mut metadata = Vec::new();
        for m in self.metadata() {
            metadata.extend_from_slice(&m.id.to_be_bytes());
            metadata.extend_from_slice(&(m.data.len() as u32).to_be_bytes());
            let mut value = m.data.clone();
            if m.id == 1 && value.len() == 4 {
                value.copy_from_slice(&3u32.to_be_bytes());
            }
            if m.id == 4 && value.len() == 8 {
                value[4..].copy_from_slice(
                    &u32::try_from(data_size)
                        .map_err(|_| Error::LimitExceeded("PKG metadata data size exceeds 4 GiB"))?
                        .to_be_bytes(),
                );
            }
            metadata.extend(value);
        }
        metadata.resize(aligned(metadata.len() as u64)? as usize, 0);
        let data_offset = 0xc0 + metadata.len() as u64 + 64;
        let package_size = data_offset
            .checked_add(data_size)
            .and_then(|n| n.checked_add(96))
            .ok_or(Error::LimitExceeded("PKG size"))?;
        let mut header = [0; 128];
        header[..4].copy_from_slice(b"\x7fPKG");
        header[7] = 1;
        put32(&mut header, 8, 0xc0);
        put32(&mut header, 12, self.metadata().len() as u32);
        put32(&mut header, 16, (metadata.len() + 64) as u32);
        put32(&mut header, 20, count as u32);
        put64(&mut header, 24, package_size);
        put64(&mut header, 32, data_offset);
        put64(&mut header, 40, data_size);
        let mut qa = Sha1::new();
        let mut buffer = [0; 65536];
        for (i, _) in sizes.iter().enumerate().filter(|(_, s)| **s != 0) {
            cancelled(cancel)?;
            if let Some(data) = replacements.get(&i) {
                qa.update(data);
            } else {
                let mut reader = self.read_entry(i)?;
                loop {
                    cancelled(cancel)?;
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    qa.update(&buffer[..n]);
                }
            }
        }
        qa.update(header);
        qa.update(&table);
        let qa: [u8; 16] = qa.finalize()[..16].try_into().unwrap();
        header[48..96].copy_from_slice(&self.content_id());
        header[96..112].copy_from_slice(&qa);
        let mut seed = [0; 64];
        seed[..8].copy_from_slice(&qa[..8]);
        seed[8..16].copy_from_slice(&qa[..8]);
        seed[16..24].copy_from_slice(&qa[8..]);
        seed[24..32].copy_from_slice(&qa[8..]);
        seed[56..].fill(255);
        header[112..].copy_from_slice(&Sha1::digest(seed)[..16]);
        let hs: [u8; 16] = Sha1::digest(header)[3..19].try_into().unwrap();
        let ms: [u8; 16] = Sha1::digest(&metadata)[3..19].try_into().unwrap();
        let mut mp = [0; 48];
        debug_crypt(&ms, 0, &mut mp);
        let mut hp = mp;
        debug_crypt(&hs, 0, &mut hp);
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let scratch = loop {
            let path = parent.join(format!(
                ".pkg-liberate-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => break Scratch(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        };
        let staged = scratch.0.join("output.pkg");
        let mut file = File::create_new(&staged)?;
        for part in [&header[..], &hs, &hp, &metadata, &ms, &mp] {
            file.write_all(part)?;
        }
        progress(0, data_size);
        debug_crypt(&qa, 0, &mut table);
        file.write_all(&table)?;
        let mut position = table.len() as u64;
        for (i, size) in sizes.iter().enumerate() {
            cancelled(cancel)?;
            if *size == 0 {
                continue;
            }
            let mut reader: Box<dyn Read + '_> = if let Some(data) = replacements.get(&i) {
                Box::new(data.as_slice())
            } else {
                Box::new(self.read_entry(i)?)
            };
            let mut remaining = *size;
            while remaining != 0 {
                cancelled(cancel)?;
                let n = remaining.min(buffer.len() as u64) as usize;
                reader.read_exact(&mut buffer[..n])?;
                let padded = aligned(n as u64)? as usize;
                buffer[n..padded].fill(0);
                debug_crypt(&qa, position, &mut buffer[..padded]);
                file.write_all(&buffer[..padded])?;
                position += padded as u64;
                remaining -= n as u64;
                progress(position, data_size);
            }
        }
        file.write_all(&[0; 96])?;
        file.sync_all()?;
        cancelled(cancel)?;
        // A hard link publishes atomically without replacing a destination created meanwhile.
        fs::hard_link(&staged, destination)?;
        Ok(())
    }
}

impl<R: Read + Seek> LiberationSource for Package<R> {
    fn entries(&self) -> &[crate::FileEntry] {
        &self.entries
    }
    fn metadata(&self) -> &[crate::Metadata] {
        &self.metadata
    }
    fn content_id(&self) -> [u8; 48] {
        self.header.content_id
    }
    fn read_entry(&mut self, index: usize) -> Result<Box<dyn Read + '_>, Error> {
        Ok(Box::new(Package::read_entry(self, index)?))
    }
}
