//! PS3 retail/debug PKG inspection and container-plaintext extraction.
//! Inspection/extraction preserves nested SELF/EDAT/SDAT files. The separate
//! liberation API converts supported local-license NPDRM payloads.

mod liberate;
mod npdrm;
pub use liberate::{liberate_folder_to_directory_with_progress, liberate_folder_with_progress};
pub use npdrm::{Rap, self_content_id};

use aes::{
    Aes128,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use sha1::{Digest, Sha1};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

pub const MAX_ENTRIES: u32 = 1_000_000;
const MAX_METADATA: u64 = 16 * 1024 * 1024;
// Normal PS3 release key: pinned RPCS3 Crypto/key_vault.h (see docs/ps3.md).
const RETAIL_KEY: [u8; 16] = [
    0x2e, 0x7b, 0x71, 0xd7, 0xc9, 0xc9, 0xa1, 0x4e, 0xa3, 0x22, 0x1f, 0x18, 0x88, 0x28, 0xb8, 0xf8,
];

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    LimitExceeded(&'static str),
    UnsafePath(String),
    Cancelled,
    IncompleteExtraction { path: PathBuf, source: Box<Error> },
    ConversionFile { path: String, source: Box<Error> },
    Io(io::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(s) => write!(f, "malformed PS3 package: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported PS3 package: {s}"),
            Self::LimitExceeded(s) => write!(f, "PS3 package limit exceeded: {s}"),
            Self::UnsafePath(s) => write!(f, "unsafe or conflicting extraction path: {s:?}"),
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::IncompleteExtraction { path, source } => {
                write!(f, "incomplete extraction at {}: {source}", path.display())
            }
            Self::ConversionFile { path, source } => write!(f, "cannot convert {path}: {source}"),
            Self::Io(e) => write!(f, "package I/O failure: {e}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::IncompleteExtraction { source, .. } => Some(source.as_ref()),
            Self::ConversionFile { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Self::Malformed("truncated input")
        } else {
            Self::Io(e)
        }
    }
}

#[derive(Debug)]
pub struct Header {
    pub release_type: u16,
    pub platform: u16,
    pub metadata_offset: u32,
    pub metadata_count: u32,
    pub metadata_size: u32,
    pub entry_count: u32,
    pub package_size: u64,
    pub data_offset: u64,
    pub data_size: u64,
    pub content_id: [u8; 48],
    pub qa_digest: [u8; 16],
    pub nonce: [u8; 16],
}

#[derive(Debug)]
pub struct Metadata {
    pub id: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
}

#[derive(Debug)]
pub struct FileEntry {
    path: String,
    offset: u64,
    size: u64,
    flags: u32,
}
impl FileEntry {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Offset relative to the encrypted data region; zero for implicit directories.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn flags(&self) -> u32 {
        self.flags
    }
    pub fn kind(&self) -> FileKind {
        if self.flags & 0xff == 4 {
            FileKind::Directory
        } else {
            FileKind::File
        }
    }
}

pub struct Package<R> {
    reader: R,
    header: Header,
    metadata: Vec<Metadata>,
    entries: Vec<FileEntry>,
    cipher: Aes128,
}

fn be32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn be64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap())
}
fn range(offset: u64, size: u64, total: u64) -> Result<(), Error> {
    if offset.checked_add(size).is_none_or(|end| end > total) {
        return Err(Error::Malformed(
            "range outside declared region (damaged input or unsupported keyset, including IDU)",
        ));
    }
    Ok(())
}

impl<R: Read + Seek> Package<R> {
    pub fn open(mut reader: R) -> Result<Self, Error> {
        let total = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = [0; 0xc0];
        reader.read_exact(&mut bytes)?;
        if &bytes[..4] != b"\x7fPKG" {
            return Err(Error::Malformed("bad magic"));
        }
        let header = Header {
            release_type: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
            platform: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            metadata_offset: be32(&bytes, 8),
            metadata_count: be32(&bytes, 12),
            metadata_size: be32(&bytes, 16),
            entry_count: be32(&bytes, 20),
            package_size: be64(&bytes, 24),
            data_offset: be64(&bytes, 32),
            data_size: be64(&bytes, 40),
            content_id: bytes[48..96].try_into().unwrap(),
            qa_digest: bytes[96..112].try_into().unwrap(),
            nonce: bytes[112..128].try_into().unwrap(),
        };
        if !matches!(header.release_type, 0 | 0x8000) {
            return Err(Error::Unsupported("release type"));
        }
        if header.platform != 1 {
            return Err(Error::Unsupported("platform (PSP/Vita/PSM are not PS3)"));
        }
        if header.package_size != total {
            return Err(Error::Malformed(
                "declared package size differs from input length; split packages are unsupported",
            ));
        }
        if header.metadata_offset < 0xc0 || header.data_offset < 0xc0 {
            return Err(Error::Malformed("metadata/data overlaps header"));
        }
        range(
            header.metadata_offset.into(),
            header.metadata_size.into(),
            header.data_offset,
        )?;
        range(header.data_offset, header.data_size, total)?;
        range(0, u64::from(header.entry_count) * 32, header.data_size)?;
        if header.entry_count > MAX_ENTRIES {
            return Err(Error::LimitExceeded("entry count"));
        }
        if header.metadata_count > 65536 || u64::from(header.metadata_size) > MAX_METADATA {
            return Err(Error::LimitExceeded("metadata"));
        }
        let mut metadata = Vec::new();
        let mut position = 0u64;
        let mut ids = HashSet::new();
        reader.seek(SeekFrom::Start(header.metadata_offset.into()))?;
        for _ in 0..header.metadata_count {
            range(position, 8, header.metadata_size.into())?;
            let mut packet = [0; 8];
            reader.read_exact(&mut packet)?;
            let id = be32(&packet, 0);
            let size = be32(&packet, 4);
            position += 8;
            range(position, size.into(), header.metadata_size.into())?;
            if !ids.insert(id) {
                return Err(Error::Malformed("duplicate metadata ID"));
            }
            let mut data = vec![0; size as usize];
            reader.read_exact(&mut data)?;
            metadata.push(Metadata { id, data });
            position += u64::from(size);
        }
        let mut pkg = Self {
            reader,
            header,
            metadata,
            entries: Vec::new(),
            cipher: Aes128::new(&RETAIL_KEY.into()),
        };
        pkg.read_table()?;
        Ok(pkg)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn metadata(&self) -> &[Metadata] {
        &self.metadata
    }
    /// Sorted application tree, including inferred parent directories.
    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    fn read_at(&mut self, offset: u64, data: &mut [u8]) -> Result<(), Error> {
        range(offset, data.len() as u64, self.header.data_size)?;
        self.reader
            .seek(SeekFrom::Start(self.header.data_offset + offset))?;
        self.reader.read_exact(data)?;
        self.crypt(offset, data);
        Ok(())
    }

    fn crypt(&self, mut offset: u64, mut data: &mut [u8]) {
        while !data.is_empty() {
            let block = offset / 16;
            let skip = (offset % 16) as usize;
            let stream: [u8; 16] = if self.header.release_type == 0x8000 {
                let counter =
                    u128::from_be_bytes(self.header.nonce).wrapping_add(u128::from(block));
                let mut stream = counter.to_be_bytes().into();
                self.cipher.encrypt_block(&mut stream);
                stream.into()
            } else {
                let mut input = [0; 64];
                input[..8].copy_from_slice(&self.header.qa_digest[..8]);
                input[8..16].copy_from_slice(&self.header.qa_digest[..8]);
                input[16..24].copy_from_slice(&self.header.qa_digest[8..]);
                input[24..32].copy_from_slice(&self.header.qa_digest[8..]);
                input[56..].copy_from_slice(&block.to_be_bytes());
                Sha1::digest(input)[..16].try_into().unwrap()
            };
            let n = data.len().min(16 - skip);
            for (byte, key) in data[..n].iter_mut().zip(&stream[skip..]) {
                *byte ^= key;
            }
            data = &mut data[n..];
            offset += n as u64;
        }
    }

    fn read_table(&mut self) -> Result<(), Error> {
        let mut tree = BTreeMap::<String, FileEntry>::new();
        let mut explicit = HashSet::new();
        let mut path_bytes = 0usize;
        let table_size = u64::from(self.header.entry_count) * 32;
        for index in 0..self.header.entry_count {
            let mut record = [0; 32];
            self.read_at(u64::from(index) * 32, &mut record)?;
            let name_offset = u64::from(be32(&record, 0));
            let name_size = be32(&record, 4);
            let offset = be64(&record, 8);
            let size = be64(&record, 16);
            let flags = be32(&record, 24);
            if name_size == 0 || name_size > 4096 {
                return Err(Error::LimitExceeded(
                    "entry name length (or unsupported keyset)",
                ));
            }
            if flags & !0x8000_00ff != 0
                || !matches!(flags & 0xff, 1..=4 | 9)
                || be32(&record, 28) != 0
            {
                return Err(Error::Unsupported(
                    "entry kind/flags/padding (PSP and IDU are unsupported)",
                ));
            }
            range(offset, size, self.header.data_size)?;
            if name_offset < table_size || (size != 0 && offset < table_size) {
                return Err(Error::Malformed("entry name/payload overlaps table"));
            }
            if flags & 0xff == 4 && size != 0 {
                return Err(Error::Malformed("directory has file payload"));
            }
            let mut name = vec![0; name_size as usize];
            self.read_at(name_offset, &mut name)?;
            while name.last() == Some(&0) {
                name.pop();
            }
            let path = String::from_utf8(name)
                .map_err(|_| Error::Unsupported("non-ASCII extraction path"))?;
            if path.split('/').count() > 128 {
                return Err(Error::LimitExceeded("path depth"));
            }
            if !path.split('/').all(pkg_fs::valid_component)
                || path.eq_ignore_ascii_case(pkg_fs::MARKER)
            {
                return Err(Error::UnsafePath(path));
            }
            if !explicit.insert(path.to_ascii_lowercase()) {
                return Err(Error::UnsafePath(path));
            }
            let entry = FileEntry {
                path: path.clone(),
                offset,
                size,
                flags,
            };
            Self::insert(&mut tree, entry, &mut path_bytes, false)?;
            let mut parent = path.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                Self::insert(
                    &mut tree,
                    FileEntry {
                        path: prefix.into(),
                        offset: 0,
                        size: 0,
                        flags: 4,
                    },
                    &mut path_bytes,
                    true,
                )?;
                parent = prefix;
            }
        }
        self.entries = tree.into_values().collect();
        Ok(())
    }

    fn insert(
        tree: &mut BTreeMap<String, FileEntry>,
        entry: FileEntry,
        bytes: &mut usize,
        implicit: bool,
    ) -> Result<(), Error> {
        let key = entry.path.to_ascii_lowercase();
        if key == pkg_fs::MARKER {
            return Err(Error::UnsafePath(entry.path));
        }
        if let Some(old) = tree.get(&key) {
            if old.path != entry.path
                || old.kind() != FileKind::Directory
                || entry.kind() != FileKind::Directory
            {
                return Err(Error::UnsafePath(entry.path));
            }
            if !implicit {
                tree.insert(key, entry);
            }
            return Ok(());
        }
        *bytes += entry.path.len();
        if tree.len() >= MAX_ENTRIES as usize || *bytes > 64 * 1024 * 1024 {
            return Err(Error::LimitExceeded("tree metadata"));
        }
        tree.insert(key, entry);
        Ok(())
    }

    pub fn read_entry(&mut self, index: usize) -> Result<EntryReader<'_, R>, Error> {
        let entry = self
            .entries
            .get(index)
            .ok_or(Error::Malformed("entry index"))?;
        if entry.kind() != FileKind::File {
            return Err(Error::Unsupported("cannot read directory as file"));
        }
        Ok(EntryReader {
            package: self,
            index,
            position: 0,
        })
    }

    fn read_named(&mut self, name: &str, limit: u64) -> Result<Option<Vec<u8>>, Error> {
        let Some(index) = self.entries.iter().position(|e| e.path == name) else {
            return Ok(None);
        };
        if self.entries[index].size > limit {
            return Err(Error::LimitExceeded("metadata file size"));
        }
        let mut data = Vec::with_capacity(self.entries[index].size as usize);
        self.read_entry(index)?.read_to_end(&mut data)?;
        Ok(Some(data))
    }
    pub fn read_param_sfo(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.read_named("PARAM.SFO", MAX_METADATA)
    }
    pub fn read_icon0(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.read_named("ICON0.PNG", 4 * 1024 * 1024)
    }

    pub fn extract(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.extract_with_progress(path, || false, |_, _| {})
    }
    pub fn extract_with_cancel(
        &mut self,
        path: impl AsRef<Path>,
        cancelled: impl FnMut() -> bool,
    ) -> Result<(), Error> {
        self.extract_with_progress(path, cancelled, |_, _| {})
    }
    /// Write a new tree, reporting decoded bytes and checking cancellation between
    /// entries/64 KiB chunks. Failed output retains `.pkg-tools-incomplete`.
    pub fn extract_with_progress(
        &mut self,
        path: impl AsRef<Path>,
        mut cancelled: impl FnMut() -> bool,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        #[cfg(not(unix))]
        {
            let _ = (path, cancelled, progress);
            Err(Error::Unsupported(
                "safe disk extraction currently requires Unix",
            ))
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            if cancelled() {
                return Err(Error::Cancelled);
            }
            let total = self.entries.iter().try_fold(0u64, |sum, e| {
                sum.checked_add(e.size)
                    .ok_or(Error::LimitExceeded("total extracted size"))
            })?;
            progress(0, total);
            let path = path.as_ref();
            let output = pkg_fs::Output::create(path)?;
            let result = (|| {
                output.mark_incomplete()?;
                let mut completed = 0;
                let mut buffer = [0; 65536];
                for index in 0..self.entries.len() {
                    if cancelled() {
                        return Err(Error::Cancelled);
                    }
                    let entry = &self.entries[index];
                    if entry.kind() == FileKind::Directory {
                        output.create_directory(&entry.path)?;
                        continue;
                    }
                    let mut out = output.create_file(&entry.path)?;
                    let mut reader = self.read_entry(index)?;
                    loop {
                        if cancelled() {
                            return Err(Error::Cancelled);
                        }
                        let n = match reader.read(&mut buffer) {
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            result => result?,
                        };
                        if n == 0 {
                            break;
                        }
                        out.write_all(&buffer[..n])?;
                        completed += n as u64;
                        progress(completed, total);
                    }
                    out.flush()?;
                }
                if cancelled() {
                    return Err(Error::Cancelled);
                }
                output.finish()?;
                Ok(())
            })();
            result.map_err(|source| Error::IncompleteExtraction {
                path: path.to_owned(),
                source: Box::new(source),
            })
        }
    }
}

pub struct EntryReader<'a, R> {
    package: &'a mut Package<R>,
    index: usize,
    position: u64,
}
impl<R: Read + Seek> Read for EntryReader<'_, R> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let entry = &self.package.entries[self.index];
        let n = (entry.size - self.position)
            .min(data.len() as u64)
            .min(65536) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.package
            .read_at(entry.offset + self.position, &mut data[..n])
            .map_err(|e| match e {
                Error::Io(e) => e,
                other => io::Error::new(io::ErrorKind::InvalidData, other),
            })?;
        self.position += n as u64;
        Ok(n)
    }
}
impl<R: Read + Seek> Seek for EntryReader<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.package.entries[self.index].size;
        let new = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => size.checked_add_signed(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
        };
        self.position = new
            .filter(|n| *n <= size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek outside entry"))?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests;
