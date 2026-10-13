//! PS4 inspection and streaming fake-package extraction. No signature authentication.

mod crypto;
mod extract;
mod input;
mod pfs;
mod pfsc;
pub use extract::{EntryReader, FileEntry, FileKind, Game};
#[cfg(test)]
mod tests;

use std::{
    collections::HashSet,
    fmt,
    io::{self, Read, Seek, SeekFrom},
};

pub const MAX_ENTRIES: u32 = 65_536;
pub const MAX_SFO_SIZE: u32 = 16 * 1024 * 1024;
const HEADER_SIZE: u64 = 0x1100;

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    DecryptionUnavailable {
        entry_id: u32,
        key_index: u8,
    },
    LimitExceeded(&'static str),
    KeyRecoveryFailed,
    Cancelled,
    UnsafePath(String),
    IncompleteExtraction {
        path: std::path::PathBuf,
        source: Box<Error>,
    },
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(s) => write!(f, "malformed PS4 package: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported package: {s}"),
            Self::DecryptionUnavailable {
                entry_id,
                key_index,
            } => write!(
                f,
                "decryption material unavailable for entry {entry_id:#x} (key index {key_index})"
            ),
            Self::LimitExceeded(s) => write!(f, "package limit exceeded: {s}"),
            Self::KeyRecoveryFailed => write!(
                f,
                "fake-key recovery failed: unsupported keyset or damaged key material"
            ),
            Self::Cancelled => write!(f, "extraction cancelled"),
            Self::UnsafePath(s) => write!(f, "unsafe or conflicting extraction path: {s:?}"),
            Self::IncompleteExtraction { path, source } => {
                write!(f, "incomplete extraction at {}: {source}", path.display())
            }
            Self::Io(e) => write!(f, "package I/O failure: {e}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::IncompleteExtraction { source, .. } => Some(source),
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
    pub flags: u32,
    pub content_id: [u8; 48],
    pub drm_type: u32,
    pub content_type: u32,
    pub content_flags: u32,
    pub entry_count: u32,
    pub entry_table_offset: u32,
    pub body_offset: u64,
    pub body_size: u64,
    pub pfs_flags: u64,
    pub pfs_offset: u64,
    pub pfs_size: u64,
    pub package_size: u64,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: u32,
    pub name_offset: u32,
    pub flags1: u32,
    pub flags2: u32,
    pub offset: u32,
    pub size: u32,
}
impl Entry {
    pub fn encrypted(&self) -> bool {
        self.flags1 & 0x8000_0000 != 0
    }
    pub fn key_index(&self) -> u8 {
        ((self.flags2 >> 12) & 15) as u8
    }
}

/// Container entries are not application/PFS files. Memory scales with entry
/// count (capped), never package payload size. Input must be a complete package.
pub struct Package<R> {
    reader: R,
    header: Header,
    entries: Vec<Entry>,
}

fn range(offset: u64, size: u64, total: u64) -> Result<(), Error> {
    if offset.checked_add(size).is_none_or(|end| end > total) {
        return Err(Error::Malformed("range outside package"));
    }
    Ok(())
}
fn be32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn be64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap())
}

impl<R: Read + Seek> Package<R> {
    pub fn open(mut reader: R) -> Result<Self, Error> {
        let total = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut magic = [0; 4];
        reader.read_exact(&mut magic)?;
        match &magic {
            b"\x7fPKG" => return Err(Error::Unsupported("PS3 inspection is not implemented")),
            b"\x7fCNT" => {}
            _ => return Err(Error::Malformed("bad magic")),
        }
        if total < HEADER_SIZE {
            return Err(Error::Malformed("truncated header"));
        }
        reader.seek(SeekFrom::Start(0))?;
        let mut data = [0; 0x5a0];
        reader.read_exact(&mut data)?;
        let header = Header {
            flags: be32(&data, 4),
            content_id: data[0x40..0x70].try_into().unwrap(),
            drm_type: be32(&data, 0x70),
            content_type: be32(&data, 0x74),
            content_flags: be32(&data, 0x78),
            entry_count: be32(&data, 0x10),
            entry_table_offset: be32(&data, 0x18),
            body_offset: be64(&data, 0x20),
            body_size: be64(&data, 0x28),
            pfs_flags: be64(&data, 0x408),
            pfs_offset: be64(&data, 0x410),
            pfs_size: be64(&data, 0x418),
            package_size: be64(&data, 0x430),
        };
        if header.package_size != total {
            return Err(Error::Malformed(
                "declared package size differs from input length",
            ));
        }
        range(header.body_offset, header.body_size, total)?;
        range(header.pfs_offset, header.pfs_size, total)?;
        range(be64(&data, 0x420), be64(&data, 0x428), total)?;
        if u64::from(header.entry_table_offset) < HEADER_SIZE {
            return Err(Error::Malformed("entry table overlaps header"));
        }
        range(
            u64::from(header.entry_table_offset),
            u64::from(header.entry_count) * 32,
            total,
        )?;
        if header.entry_count > MAX_ENTRIES {
            return Err(Error::LimitExceeded("more than 65536 container entries"));
        }
        reader.seek(SeekFrom::Start(u64::from(header.entry_table_offset)))?;
        let mut entries = Vec::with_capacity(header.entry_count as usize);
        let mut ids = HashSet::with_capacity(header.entry_count as usize);
        for _ in 0..header.entry_count {
            let mut record = [0; 32];
            reader.read_exact(&mut record)?;
            let entry = Entry {
                id: be32(&record, 0),
                name_offset: be32(&record, 4),
                flags1: be32(&record, 8),
                flags2: be32(&record, 12),
                offset: be32(&record, 16),
                size: be32(&record, 20),
            };
            range(u64::from(entry.offset), u64::from(entry.size), total)?;
            if entry.size != 0 && u64::from(entry.offset) < HEADER_SIZE {
                return Err(Error::Malformed("entry data overlaps header"));
            }
            if !ids.insert(entry.id) {
                return Err(Error::Malformed("duplicate container entry ID"));
            }
            entries.push(entry);
        }
        Ok(Self {
            reader,
            header,
            entries,
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Read plaintext PARAM.SFO bytes for `psf::parse`. Absence is `Ok(None)`;
    /// encrypted metadata is a distinct error, not missing or malformed SFO.
    pub fn read_param_sfo(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.read_plaintext_entry(0x1000, MAX_SFO_SIZE, "PARAM.SFO exceeds 16 MiB")
    }

    /// Read plaintext icon0.png without opening or decrypting the application tree.
    /// Missing artwork is `None`; encrypted artwork reports unavailable material.
    pub fn read_icon0(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.read_plaintext_entry(0x1200, 4 * 1024 * 1024, "icon0.png exceeds 4 MiB")
    }

    fn read_plaintext_entry(
        &mut self,
        id: u32,
        limit: u32,
        limit_message: &'static str,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(entry) = self.entries.iter().find(|e| e.id == id) else {
            return Ok(None);
        };
        if entry.encrypted() {
            return Err(Error::DecryptionUnavailable {
                entry_id: entry.id,
                key_index: entry.key_index(),
            });
        }
        if entry.size > limit {
            return Err(Error::LimitExceeded(limit_message));
        }
        self.reader.seek(SeekFrom::Start(u64::from(entry.offset)))?;
        let mut data = vec![0; entry.size as usize];
        self.reader.read_exact(&mut data)?;
        Ok(Some(data))
    }
}
