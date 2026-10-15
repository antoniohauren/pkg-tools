//! Streaming ZArchive v1 creation. Parents must be added before children.
//! Payload and chunk indexes use bounded RAM; directory metadata stays in memory.
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const BLOCK: usize = 65536;
const MAX_LOGICAL: u64 = (1 << 48) - 1;
static SERIAL: AtomicU64 = AtomicU64::new(0);

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Node {
    name: String,
    file: Option<(u64, u64)>,
    children: BTreeMap<String, usize>,
}

/// A transactional archive. Any failed addition poisons the writer.
/// Dropping it removes scratch files; `finish` publishes without overwriting.
pub struct Writer {
    output: File,
    index: File,
    destination: PathBuf,
    nodes: Vec<Node>,
    block: Vec<u8>,
    record: [u8; 40],
    chunks: u64,
    logical: u64,
    position: u64,
    names_size: u64,
    hash: Sha256,
    failed: bool,
    scratch: Scratch,
}

impl Writer {
    pub fn create(destination: impl AsRef<Path>) -> io::Result<Self> {
        let destination = destination.as_ref().to_path_buf();
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "destination exists",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let scratch = loop {
            let path = parent.join(format!(
                ".zarchive-{}-{}",
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
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        };
        let output = File::create_new(scratch.0.join("archive"))?;
        let index = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(scratch.0.join("index"))?;
        Ok(Self {
            output,
            index,
            destination,
            nodes: vec![Node {
                name: String::new(),
                file: None,
                children: BTreeMap::new(),
            }],
            block: Vec::with_capacity(BLOCK),
            record: [0; 40],
            chunks: 0,
            logical: 0,
            position: 0,
            names_size: 0,
            hash: Sha256::new(),
            failed: false,
            scratch,
        })
    }

    fn start(&mut self, path: &str, file: Option<(u64, u64)>) -> io::Result<()> {
        if self.failed {
            return Err(invalid("archive writer is poisoned"));
        }
        self.failed = true;
        let parts: Vec<_> = path.split('/').collect();
        for part in &parts {
            // Pinned reader reads the first length byte twice for extended names.
            if part.is_empty()
                || *part == "."
                || *part == ".."
                || part.len() > 127
                || part.contains(['\\', '\0', ':'])
            {
                return Err(invalid("invalid archive path"));
            }
        }
        let mut parent = 0;
        for part in &parts[..parts.len() - 1] {
            let child = *self.nodes[parent]
                .children
                .get(&part.to_ascii_lowercase())
                .ok_or_else(|| invalid("parent directory missing"))?;
            if self.nodes[child].file.is_some() || self.nodes[child].name != *part {
                return Err(invalid("parent is a file or differs in case"));
            }
            parent = child;
        }
        let name = parts.last().unwrap();
        let key = name.to_ascii_lowercase();
        if self.nodes[parent].children.contains_key(&key) {
            return Err(invalid("duplicate or ASCII-case-colliding path"));
        }
        self.names_size += name.len() as u64 + 1;
        if self.names_size > 0x7fffffff || (self.nodes.len() as u64 + 1) * 16 > u32::MAX as u64 {
            return Err(invalid("archive index exceeds reader limits"));
        }
        let id = self.nodes.len();
        self.nodes[parent].children.insert(key, id);
        self.nodes.push(Node {
            name: name.to_string(),
            file,
            children: BTreeMap::new(),
        });
        Ok(())
    }

    pub fn add_directory(&mut self, path: &str) -> io::Result<()> {
        self.start(path, None)?;
        self.failed = false;
        Ok(())
    }

    /// Read exactly `size` bytes, then require EOF. Errors prevent publication.
    pub fn add_file(&mut self, path: &str, size: u64, mut input: impl Read) -> io::Result<()> {
        self.start(path, Some((self.logical, size)))?;
        let end = self
            .logical
            .checked_add(size)
            .filter(|n| *n <= MAX_LOGICAL)
            .ok_or_else(|| invalid("48-bit logical stream limit exceeded"))?;
        let mut remaining = size;
        while remaining > 0 {
            let count = remaining.min((BLOCK - self.block.len()) as u64) as usize;
            let start = self.block.len();
            self.block.resize(start + count, 0);
            input.read_exact(&mut self.block[start..])?;
            remaining -= count as u64;
            if self.block.len() == BLOCK {
                self.store_block()?;
            }
        }
        let mut extra = [0];
        loop {
            match input.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err(invalid("file exceeds declared size")),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        self.logical = end;
        self.failed = false;
        Ok(())
    }

    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.output.write_all(bytes)?;
        self.hash.update(bytes);
        self.position = self
            .position
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("output too large"))?;
        Ok(())
    }

    fn store_block(&mut self) -> io::Result<()> {
        if (self.chunks + 1).div_ceil(16) * 40 > u32::MAX as u64 {
            return Err(invalid("chunk index exceeds reader limit"));
        }
        let encoded = ruzstd::encoding::compress_to_vec(
            self.block.as_slice(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let data = if encoded.len() < BLOCK {
            encoded
        } else {
            self.block.clone()
        };
        let slot = (self.chunks % 16) as usize;
        if slot == 0 {
            self.record[..8].copy_from_slice(&self.position.to_be_bytes());
        }
        self.record[8 + slot * 2..10 + slot * 2]
            .copy_from_slice(&((data.len() - 1) as u16).to_be_bytes());
        self.emit(&data)?;
        self.chunks += 1;
        if slot == 15 {
            self.index.write_all(&self.record)?;
            self.record = [0; 40];
        }
        self.block.clear();
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<()> {
        if self.failed {
            return Err(invalid("archive writer is poisoned"));
        }
        if self.logical == 0 {
            return Err(invalid(
                "zero-payload archives are unsupported by the pinned reader",
            ));
        }
        if !self.block.is_empty() {
            self.block.resize(BLOCK, 0);
            self.store_block()?;
        }
        if !self.chunks.is_multiple_of(16) {
            self.index.write_all(&self.record)?;
        }
        let mut sections = vec![(0, self.position)];
        self.emit(&[0; 8][..((8 - self.position % 8) % 8) as usize])?;
        let start = self.position;
        self.index.rewind()?;
        let mut buffer = [0; BLOCK];
        loop {
            let n = self.index.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            self.emit(&buffer[..n])?;
        }
        sections.push((start, self.position - start));
        let start = self.position;
        let mut names = vec![0x7fffffff];
        for i in 1..self.nodes.len() {
            names.push((self.position - start) as u32);
            let name = self.nodes[i].name.clone();
            let len = name.len();
            self.emit(&[len as u8])?;
            self.emit(name.as_bytes())?;
        }
        sections.push((start, self.position - start));
        let start = self.position;
        let mut order = vec![0];
        let mut cursor = 0;
        while cursor < order.len() {
            let id = order[cursor];
            let node = &self.nodes[id];
            let words = if let Some((offset, size)) = node.file {
                [
                    names[id] | 0x80000000,
                    offset as u32,
                    size as u32,
                    ((offset >> 32) as u32) | (((size >> 32) as u32) << 16),
                ]
            } else {
                let words = [names[id], order.len() as u32, node.children.len() as u32, 0];
                order.extend(node.children.values().copied());
                words
            };
            for word in words {
                self.emit(&word.to_be_bytes())?;
            }
            cursor += 1;
        }
        sections.push((start, self.position - start));
        sections.extend([(self.position, 0); 2]);
        let mut footer = Vec::with_capacity(144);
        for (offset, size) in sections {
            footer.extend(offset.to_be_bytes());
            footer.extend(size.to_be_bytes());
        }
        footer.extend([0; 32]);
        footer.extend((self.position + 144).to_be_bytes());
        footer.extend(0x61bf3a01u32.to_be_bytes());
        footer.extend(0x169f52d6u32.to_be_bytes());
        self.hash.update(&footer);
        footer[96..128].copy_from_slice(&self.hash.clone().finalize());
        self.output.write_all(&footer)?;
        self.output.sync_all()?;
        // Same-filesystem hard linking publishes atomically and never replaces a destination.
        fs::hard_link(self.scratch.0.join("archive"), &self.destination)
    }
}

/// Archive a stable directory tree. UTF-8 names only; symlinks/special files rejected.
/// Destination must be outside the source tree. Do not mutate the tree during packing.
pub fn pack_directory(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> io::Result<()> {
    let source = source.as_ref();
    if !fs::symlink_metadata(source)?.file_type().is_dir() {
        return Err(invalid("source must be a directory, not a symlink"));
    }
    let root = fs::canonicalize(source)?;
    let destination = destination.as_ref();
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if fs::canonicalize(parent)?.starts_with(&root) {
        return Err(invalid("destination must be outside source tree"));
    }
    let mut writer = Writer::create(destination)?;
    let mut pending = vec![String::new()];
    while let Some(relative) = pending.pop() {
        let mut entries = fs::read_dir(root.join(&relative))?.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("non-UTF-8 filename"))?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let kind = entry.file_type()?;
            if kind.is_dir() {
                writer.add_directory(&path)?;
                pending.push(path);
            } else if kind.is_file() {
                let file = File::open(entry.path())?;
                writer.add_file(&path, file.metadata()?.len(), file)?;
            } else {
                return Err(invalid("symlinks and special files are unsupported"));
            }
        }
    }
    writer.finish()
}
