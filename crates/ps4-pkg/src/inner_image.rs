//! Clear D32 PFS images and raw-block PFSC wrappers, not installable packages.
//!
//! This is the image layer only: callers select the inner application namespace
//! after container-resource classification. No SFO edits, keys or PKG records are
//! generated. Payload callbacks must fill the entire requested slice or fail and
//! must provide a stable snapshot for the duration of a write.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) const BLOCK: usize = 0x10000;
const INODE: usize = 0xa8;
const PER_BLOCK: usize = BLOCK / INODE;
const MIN_BLOCKS: u64 = 0x55;
const MAX_ENTRIES: usize = 32_768;
const PFSC_TABLE: u64 = 0x400;
const DIRECTORY_BIT: u32 = 0x2000_0000;
const COLLISION_BIT: u32 = 0x8000_0000;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub(crate) fn check(cancelled: &mut impl FnMut() -> bool) -> io::Result<()> {
    if cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "image write cancelled",
        ))
    } else {
        Ok(())
    }
}

/// Explicit application path; parents must be declared, including empty directories.
#[derive(Clone, Debug)]
pub struct Entry {
    pub path: String,
    /// None means directory; Some(0) means empty regular file.
    pub size: Option<u64>,
}

struct Node {
    path: String,
    size: u64,
    start: u32,
    links: u16,
    flags: u32,
    data: Data,
}

enum Data {
    Bytes(Vec<u8>),
    Directory(Vec<u8>),
    File(usize),
}

impl Node {
    fn directory(&self) -> bool {
        matches!(self.data, Data::Directory(_))
    }
    fn blocks(&self) -> u64 {
        self.size.div_ceil(BLOCK as u64)
    }
}

/// Validated layout. Metadata memory scales with capped paths, never payload size.
/// All offsets and sizes are checked before any output or payload callback.
pub struct InnerImage {
    nodes: Vec<Node>,
    inode_blocks: u64,
    blocks: u64,
    timestamp: i64,
}

fn hash(path: &str) -> u32 {
    std::iter::once(b'/')
        .chain(path.bytes())
        .fold(0u32, |h, b| {
            h.wrapping_mul(31)
                .wrapping_add(u32::from(b.to_ascii_uppercase()))
        })
}

pub(crate) fn dirent(out: &mut Vec<u8>, name: &str, inode: u32, kind: u32, blocked: bool) {
    let mut size = (17 + name.len()).next_multiple_of(8);
    if blocked && out.len() % BLOCK + size > BLOCK {
        out.resize(out.len().next_multiple_of(BLOCK), 0);
    }
    // A zero tail must still have room for a complete 16-byte dirent header.
    if blocked {
        let remaining = BLOCK - (out.len() % BLOCK + size);
        if remaining < 16 {
            size += remaining;
        }
    }
    out.extend_from_slice(&inode.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.resize(out.len() + size - 16 - name.len(), 0);
}

impl InnerImage {
    /// Plan an unsigned, unencrypted 64-KiB-block image. Paths use portable ASCII,
    /// depth <= 60, total length <= 4096; collision-resolver paths <= 255 bytes.
    /// Timestamp is explicit Unix seconds, shared by all four inode timestamps.
    /// Input order does not affect bytes; callbacks retain original entry indices.
    pub fn new(entries: &[Entry], timestamp: i64) -> io::Result<Self> {
        if entries.len() > MAX_ENTRIES {
            return Err(invalid("too many inner-image entries"));
        }
        let mut paths = BTreeMap::new();
        let mut folded = BTreeSet::new();
        for (index, entry) in entries.iter().enumerate() {
            if entry.path.len() > 4096
                || entry.path.split('/').count() > 60
                || !entry.path.split('/').all(pkg_fs::valid_component)
                || !folded.insert(entry.path.to_ascii_lowercase())
            {
                return Err(invalid("invalid or case-colliding inner-image path"));
            }
            paths.insert(entry.path.as_str(), (index, entry));
        }
        for path in paths.keys() {
            if let Some((parent, _)) = path.rsplit_once('/')
                && !paths.get(parent).is_some_and(|(_, e)| e.size.is_none())
            {
                return Err(invalid(
                    "missing directory parent or file/directory collision",
                ));
            }
        }
        let mut groups: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
        for path in paths.keys() {
            groups.entry(hash(path)).or_default().push(path);
        }
        let collision = groups.values().any(|g| g.len() > 1);
        let mut nodes = vec![
            Node {
                path: String::new(),
                size: 0,
                start: 0,
                links: 1,
                flags: 0x20010,
                data: Data::Directory(Vec::new()),
            },
            Node {
                path: String::new(),
                size: 0,
                start: 0,
                links: 1,
                flags: 0x20010,
                data: Data::Bytes(Vec::new()),
            },
        ];
        if collision {
            nodes.push(Node {
                path: String::new(),
                size: 0,
                start: 0,
                links: 1,
                flags: 0x20010,
                data: Data::Bytes(Vec::new()),
            });
        }
        let root = nodes.len();
        nodes.push(Node {
            path: String::new(),
            size: 0,
            start: 0,
            links: 3,
            flags: 0x10,
            data: Data::Directory(Vec::new()),
        });
        let mut numbers = BTreeMap::new();
        numbers.insert("", root as u32);
        for directory in [true, false] {
            for (&path, &(index, entry)) in &paths {
                if entry.size.is_none() != directory {
                    continue;
                }
                numbers.insert(path, nodes.len() as u32);
                nodes.push(Node {
                    path: path.to_owned(),
                    size: entry.size.unwrap_or(0),
                    start: 0,
                    links: if directory { 2 } else { 1 },
                    flags: 0x10,
                    data: if directory {
                        Data::Directory(Vec::new())
                    } else {
                        Data::File(index)
                    },
                });
            }
        }
        let mut lookup = Vec::new();
        let mut resolver = Vec::new();
        for (hash, group) in groups {
            let value = if group.len() == 1 {
                let path = group[0];
                numbers[path]
                    | if paths[path].1.size.is_none() {
                        DIRECTORY_BIT
                    } else {
                        0
                    }
            } else {
                let offset =
                    u32::try_from(resolver.len()).map_err(|_| invalid("collision table size"))?;
                if offset >= COLLISION_BIT {
                    return Err(invalid("collision table offset"));
                }
                for path in group {
                    if path.len() + 1 > 255 {
                        return Err(invalid("collision-resolver path exceeds 255 bytes"));
                    }
                    dirent(
                        &mut resolver,
                        &format!("/{path}"),
                        numbers[path],
                        if paths[path].1.size.is_none() { 3 } else { 2 },
                        false,
                    );
                }
                resolver.resize(resolver.len() + 24, 0);
                COLLISION_BIT | offset
            };
            lookup.extend_from_slice(&hash.to_le_bytes());
            lookup.extend_from_slice(&value.to_le_bytes());
        }
        nodes[1].data = Data::Bytes(lookup);
        if collision {
            nodes[2].data = Data::Bytes(resolver);
        }
        let mut superroot = Vec::new();
        dirent(&mut superroot, "flat_path_table", 1, 2, true);
        if collision {
            dirent(&mut superroot, "collision_resolver", 2, 2, true);
        }
        dirent(&mut superroot, "uroot", root as u32, 3, true);
        nodes[0].data = Data::Directory(superroot);
        for (i, node) in nodes.iter_mut().enumerate().skip(root) {
            if node.directory() {
                let mut bytes = Vec::new();
                let parent = node.path.rsplit_once('/').map_or("", |(p, _)| p);
                dirent(&mut bytes, ".", i as u32, 4, true);
                dirent(&mut bytes, "..", numbers[parent], 5, true);
                node.data = Data::Directory(bytes);
            }
        }
        for i in root + 1..nodes.len() {
            let (parent, name) = nodes[i]
                .path
                .rsplit_once('/')
                .unwrap_or(("", &nodes[i].path));
            let parent = numbers[parent] as usize;
            let kind = if nodes[i].directory() { 3 } else { 2 };
            let name = name.to_owned();
            if kind == 3 {
                nodes[parent].links += 1;
            }
            if let Data::Directory(bytes) = &mut nodes[parent].data {
                dirent(bytes, &name, i as u32, kind, true);
            }
        }
        let inode_blocks = nodes.len().div_ceil(PER_BLOCK) as u64;
        let mut next = 1 + inode_blocks;
        for (i, node) in nodes.iter_mut().enumerate() {
            node.size = match &node.data {
                Data::Directory(bytes) => bytes.len().div_ceil(BLOCK) as u64 * BLOCK as u64,
                Data::Bytes(bytes) => bytes.len() as u64,
                Data::File(_) => node.size,
            };
            node.start = u32::try_from(next).map_err(|_| invalid("D32 block offset overflow"))?;
            next = next
                .checked_add(node.blocks())
                .ok_or_else(|| invalid("image size overflow"))?;
            // Reference profile reserves one empty block when no collision table exists.
            if i == 1 && !collision {
                next += 1;
            }
        }
        let blocks = next.max(MIN_BLOCKS);
        if blocks > u64::from(u32::MAX) {
            return Err(invalid("D32 image block limit"));
        }
        Ok(Self {
            nodes,
            inode_blocks,
            blocks,
            timestamp,
        })
    }

    pub fn pfs_size(&self) -> u64 {
        self.blocks * BLOCK as u64
    }

    pub(crate) fn timestamp(&self) -> i64 {
        self.timestamp
    }

    fn pfsc_start(&self) -> u64 {
        (PFSC_TABLE + (self.blocks + 1) * 8).next_multiple_of(BLOCK as u64)
    }

    pub fn pfsc_size(&self) -> u64 {
        self.pfsc_start() + self.pfs_size()
    }

    /// Stream raw PFS or its raw-block PFSC wrapper. No seek, payload buffering,
    /// encryption or authentication. On failure caller must discard partial stream.
    /// Callback receives original entry index, file-relative offset and <=64 KiB slice.
    pub fn write(
        &self,
        output: &mut impl Write,
        wrapped: bool,
        mut read: impl FnMut(usize, u64, &mut [u8]) -> io::Result<()>,
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        check(&mut cancelled)?;
        let mut block = vec![0; BLOCK];
        if wrapped {
            block[..4].copy_from_slice(b"PFSC");
            put32(&mut block, 8, 6);
            put32(&mut block, 12, BLOCK as u32);
            put64(&mut block, 16, BLOCK as u64);
            put64(&mut block, 24, PFSC_TABLE);
            put64(&mut block, 32, self.pfsc_start());
            put64(&mut block, 40, self.pfs_size());
            output.write_all(&block[..PFSC_TABLE as usize])?;
            for index in 0..=self.blocks {
                if index.is_multiple_of(8192) {
                    check(&mut cancelled)?;
                }
                output.write_all(&(self.pfsc_start() + index * BLOCK as u64).to_le_bytes())?;
            }
            block.fill(0);
            zeros(
                output,
                self.pfsc_start() - PFSC_TABLE - (self.blocks + 1) * 8,
                &block,
                &mut cancelled,
            )?;
        }
        block.fill(0);
        put64(&mut block, 0, 1);
        put64(&mut block, 8, 20130315);
        block[0x1a] = 1;
        block[0x1c] = 8;
        put32(&mut block, 0x20, BLOCK as u32);
        put64(&mut block, 0x28, 1);
        put64(&mut block, 0x30, self.nodes.len() as u64);
        put64(&mut block, 0x38, self.blocks);
        put64(&mut block, 0x40, self.inode_blocks);
        // Header embeds an S64 inode describing the contiguous D32 inode table.
        block[0x52] = 1;
        put32(&mut block, 0x54, 0x10);
        put64(&mut block, 0x58, self.inode_blocks * BLOCK as u64);
        put64(&mut block, 0x60, self.inode_blocks * BLOCK as u64);
        for offset in [0x68, 0x70, 0x78, 0x80] {
            put64(&mut block, offset, self.timestamp as u64);
        }
        put32(&mut block, 0xb0, self.inode_blocks as u32);
        put64(&mut block, 0xd8, 1);
        for i in 1..12 {
            put64(&mut block, 0xd8 + 40 * i, u64::MAX);
        }
        put32(&mut block, 0x368, 1);
        output.write_all(&block)?;
        for group in self.nodes.chunks(PER_BLOCK) {
            check(&mut cancelled)?;
            block.fill(0);
            for (i, node) in group.iter().enumerate() {
                let b = &mut block[i * INODE..(i + 1) * INODE];
                b[..2].copy_from_slice(
                    &(if node.directory() { 0x416du16 } else { 0x816d }).to_le_bytes(),
                );
                b[2..4].copy_from_slice(&node.links.to_le_bytes());
                put32(b, 4, node.flags);
                put64(b, 8, node.size);
                put64(b, 16, node.size);
                for offset in [24, 32, 40, 48] {
                    put64(b, offset, self.timestamp as u64);
                }
                put32(b, 96, node.blocks() as u32);
                put32(b, 100, node.start);
                for offset in (104..148).step_by(4) {
                    put32(b, offset, u32::MAX);
                }
            }
            output.write_all(&block)?;
        }
        let mut position = (1 + self.inode_blocks) * BLOCK as u64;
        for node in &self.nodes {
            block.fill(0);
            zeros(
                output,
                u64::from(node.start) * BLOCK as u64 - position,
                &block,
                &mut cancelled,
            )?;
            let mut offset = 0;
            while offset < node.size {
                check(&mut cancelled)?;
                block.fill(0);
                let n = (node.size - offset).min(BLOCK as u64) as usize;
                match &node.data {
                    Data::File(index) => read(*index, offset, &mut block[..n])?,
                    Data::Bytes(bytes) | Data::Directory(bytes) => {
                        let start = (offset as usize).min(bytes.len());
                        let end = (start + n).min(bytes.len());
                        block[..end - start].copy_from_slice(&bytes[start..end]);
                    }
                }
                check(&mut cancelled)?;
                output.write_all(&block)?;
                offset += n as u64;
            }
            position = (u64::from(node.start) + node.blocks()) * BLOCK as u64;
        }
        block.fill(0);
        zeros(output, self.pfs_size() - position, &block, &mut cancelled)?;
        check(&mut cancelled)
    }

    /// Publish an intermediate `.pfs` or `.pfsc` file without replacement. Parent
    /// must exist, without symlink components. Scratch uses one image's disk space;
    /// failures/cancellation remove unpublished scratch best-effort. Hard links required.
    /// Caller must keep destination parents stable (not a hostile-mutation sandbox).
    pub fn write_new(
        &self,
        destination: &Path,
        read: impl FnMut(usize, u64, &mut [u8]) -> io::Result<()>,
        cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        self.write_new_checked(destination, read, cancelled, || Ok(()))
    }

    pub(crate) fn write_new_checked(
        &self,
        destination: &Path,
        read: impl FnMut(usize, u64, &mut [u8]) -> io::Result<()>,
        mut cancelled: impl FnMut() -> bool,
        mut verify: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        check(&mut cancelled)?;
        let wrapped = match destination.extension().and_then(|s| s.to_str()) {
            Some("pfs") => false,
            Some("pfsc") => true,
            _ => {
                return Err(invalid(
                    "intermediate image requires .pfs or .pfsc, never .pkg",
                ));
            }
        };
        publish(destination, |file| {
            self.write(file, wrapped, read, &mut cancelled)?;
            file.sync_all()?;
            verify()?;
            check(&mut cancelled)
        })
    }
}

pub(crate) fn publish(
    destination: &Path,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let destination = crate::gp4::absolute(destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("image output has no parent"))?;
    crate::gp4::no_symlinks(parent)?;
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "image output exists",
        ));
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut scratch = None;
    for _ in 0..100 {
        let path = parent.join(format!(
            ".pkg-tools-image-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                scratch = Some((path, file));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
    }
    let (path, mut file) =
        scratch.ok_or_else(|| io::Error::other("cannot allocate image scratch"))?;
    let result = (|| {
        write(&mut file)?;
        fs::hard_link(&path, &destination)
    })();
    drop(file);
    let _ = fs::remove_file(path);
    result
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn zeros(
    output: &mut impl Write,
    mut count: u64,
    block: &[u8],
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<()> {
    while count > 0 {
        check(cancelled)?;
        let n = count.min(block.len() as u64) as usize;
        output.write_all(&block[..n])?;
        count -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        input::{ReadAt, Shared, le32},
        pfs::Pfs,
        pfsc::Pfsc,
    };
    use std::{cell::RefCell, io::Cursor, rc::Rc};

    fn entry(path: &str, size: Option<u64>) -> Entry {
        Entry {
            path: path.into(),
            size,
        }
    }
    fn shared(bytes: Vec<u8>) -> Shared<Cursor<Vec<u8>>> {
        let size = bytes.len() as u64;
        Shared {
            reader: Rc::new(RefCell::new(Cursor::new(bytes))),
            size,
        }
    }
    fn fill(index: usize, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        assert!(bytes.len() <= BLOCK);
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = ((offset + i as u64 + index as u64) % 251) as u8;
        }
        Ok(())
    }

    #[test]
    fn streams_wrapped_and_clear_files_directories_and_padding() {
        let entries = [
            entry("data", None),
            entry("data/boundary", Some(BLOCK as u64 + 1)),
            entry("empty", Some(0)),
            entry("empty-dir", None),
        ];
        let image = InnerImage::new(&entries, 123).unwrap();
        let mut clear = Vec::new();
        image.write(&mut clear, false, fill, || false).unwrap();
        assert_eq!(clear.len() as u64, image.pfs_size());
        let mut wrapped = Vec::new();
        image.write(&mut wrapped, true, fill, || false).unwrap();
        assert_eq!(wrapped.len() as u64, image.pfsc_size());
        let mut pfsc = Pfsc::open(shared(wrapped)).unwrap();
        let mut decoded = vec![0; clear.len()];
        pfsc.read_at(0, &mut decoded).unwrap();
        assert_eq!(clear, decoded);
        let mut pfs = Pfs::open(shared(clear), None).unwrap();
        let root = pfs.uroot().unwrap();
        let root = pfs.inode(root).unwrap();
        let children = pfs.children(&root).unwrap();
        assert_eq!(children.len(), 3);
        let data = pfs
            .inode(children.iter().find(|c| c.0 == "data").unwrap().1)
            .unwrap();
        let child = pfs.children(&data).unwrap();
        let file = pfs.inode(child[0].1).unwrap();
        let mut bytes = vec![0; BLOCK + 1];
        pfs.read_file(&file, 0, &mut bytes).unwrap();
        let mut expected = vec![0; bytes.len()];
        fill(1, 0, &mut expected[..BLOCK]).unwrap();
        fill(1, BLOCK as u64, &mut expected[BLOCK..]).unwrap();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn collision_lookup_uses_full_paths_and_unsigned_hash_order() {
        // Different ASCII paths with identical wrapping uppercase hashes.
        assert_eq!(hash("A~"), hash("B_"));
        let image = InnerImage::new(
            &[entry("A~", Some(0)), entry("B_", None), entry("z", Some(0))],
            0,
        )
        .unwrap();
        let Data::Bytes(lookup) = &image.nodes[1].data else {
            panic!()
        };
        assert_eq!(lookup.len(), 16);
        let slot = lookup
            .as_chunks::<8>()
            .0
            .iter()
            .find(|b| le32(*b, 0) == hash("A~"))
            .unwrap();
        assert_eq!(le32(slot, 4), COLLISION_BIT);
        assert!(
            lookup
                .as_chunks::<8>()
                .0
                .iter()
                .map(|b| le32(b, 0))
                .is_sorted()
        );
        let Data::Bytes(resolver) = &image.nodes[2].data else {
            panic!()
        };
        assert_eq!(&resolver[16..19], b"/A~");
        let second = le32(resolver, 12) as usize;
        assert_eq!(&resolver[second + 16..second + 19], b"/B_");
        assert!(
            resolver[second + le32(resolver, second + 12) as usize..]
                .iter()
                .all(|b| *b == 0)
        );
    }

    #[test]
    fn rejects_paths_sizes_and_inconsistent_parents_before_io() {
        for entries in [
            vec![entry("../escape", Some(1))],
            vec![entry("/absolute", Some(1))],
            vec![entry("a/b", Some(1))],
            vec![entry("a", Some(0)), entry("a/b", Some(0))],
            vec![entry("a", None), entry("A", Some(0))],
            vec![entry("a", Some(u64::MAX))],
        ] {
            assert!(InnerImage::new(&entries, 0).is_err());
        }
        assert!(InnerImage::new(&vec![entry("x", Some(0)); MAX_ENTRIES + 1], 0).is_err());
        let parent = "p".repeat(252);
        assert!(
            InnerImage::new(
                &[
                    entry(&parent, None),
                    entry(&format!("{parent}/A~"), Some(0)),
                    entry(&format!("{parent}/B_"), Some(0)),
                ],
                0
            )
            .is_err()
        );
    }

    #[test]
    fn inode_rollover_multiblock_lookup_and_directory_are_readable() {
        let entries: Vec<_> = (0..9000)
            .map(|i| entry(&format!("file{i:05}"), Some(0)))
            .collect();
        let image = InnerImage::new(&entries, 0).unwrap();
        assert!(image.inode_blocks > 1);
        assert!(image.nodes[1].blocks() > 1);
        let mut bytes = Vec::new();
        image
            .write(&mut bytes, false, |_, _, _| panic!("empty files"), || false)
            .unwrap();
        let mut pfs = Pfs::open(shared(bytes), None).unwrap();
        let root = pfs.uroot().unwrap();
        let inode = pfs.inode(root).unwrap();
        assert!(inode.size > BLOCK as u64);
        let children = pfs.children(&inode).unwrap();
        assert_eq!(children.len(), entries.len());
        for (_, number, _) in children {
            assert_eq!(pfs.inode(number).unwrap().size, 0);
        }
    }

    #[test]
    fn input_order_does_not_change_image_and_cancellation_stops_payload() {
        let entries = [entry("b", Some(1)), entry("a", Some(1))];
        let mut first = Vec::new();
        InnerImage::new(&entries, 0)
            .unwrap()
            .write(
                &mut first,
                false,
                |_, _, b| {
                    b.fill(7);
                    Ok(())
                },
                || false,
            )
            .unwrap();
        let mut reversed = entries.clone();
        reversed.reverse();
        let mut second = Vec::new();
        let image = InnerImage::new(&reversed, 0).unwrap();
        image
            .write(
                &mut second,
                false,
                |_, _, b| {
                    b.fill(7);
                    Ok(())
                },
                || false,
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            image
                .write(&mut Vec::new(), false, fill, || true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        let mut calls = 0;
        assert!(
            image
                .write(&mut io::sink(), true, fill, || {
                    calls += 1;
                    calls > 8
                })
                .is_err()
        );
        assert!(
            image
                .write(
                    &mut io::sink(),
                    false,
                    |_, _, _| Err(io::Error::other("source changed")),
                    || false
                )
                .is_err()
        );
        struct Short;
        impl Write for Short {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Ok(0)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            image
                .write(&mut Short, false, fill, || false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
    }

    #[test]
    fn publication_refuses_existing_outputs_and_cleans_failures() {
        let root =
            std::env::temp_dir().join(format!("pkg-tools-inner-test-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let output = root.join("image.pfs");
        let image = InnerImage::new(&[entry("file", Some(1))], 0).unwrap();
        assert!(
            image
                .write_new(&root.join("bad.pkg"), fill, || false)
                .is_err()
        );
        assert!(
            image
                .write_new(
                    &output,
                    |_, _, _| Err(io::Error::other("short source")),
                    || false
                )
                .is_err()
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        image.write_new(&output, fill, || false).unwrap();
        let original = fs::read(&output).unwrap();
        assert_eq!(
            image.write_new(&output, fill, || false).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&output).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let alias = root.join("alias.pfs");
            symlink(&output, &alias).unwrap();
            assert!(image.write_new(&alias, fill, || false).is_err());
            fs::remove_file(alias).unwrap();
            let parent = root.join("link");
            symlink(&root, &parent).unwrap();
            assert!(
                image
                    .write_new(&parent.join("escape.pfs"), fill, || false)
                    .is_err()
            );
            fs::remove_file(parent).unwrap();
        }
        fs::remove_file(output).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn corruption_of_pfsc_index_is_rejected() {
        let image = InnerImage::new(&[], 0).unwrap();
        let mut bytes = Vec::new();
        image.write(&mut bytes, true, fill, || false).unwrap();
        bytes[PFSC_TABLE as usize..PFSC_TABLE as usize + 8].fill(0);
        assert!(Pfsc::open(shared(bytes)).is_err());
    }

    #[test]
    fn large_file_layout_and_pfsc_index_rollover_need_no_payload_allocation() {
        let image =
            InnerImage::new(&[entry("large", Some(4 * 1024 * 1024 * 1024 + 1))], 0).unwrap();
        assert!(image.pfs_size() > u64::from(u32::MAX));
        assert!(image.pfsc_start() > BLOCK as u64);
        // Capture only the wrapper, abort before PFS data; no multi-GiB fixture.
        struct Prefix {
            bytes: Vec<u8>,
            limit: usize,
        }
        impl Write for Prefix {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.bytes.len() == self.limit {
                    return Err(io::Error::other("prefix complete"));
                }
                let n = bytes.len().min(self.limit - self.bytes.len());
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut prefix = Prefix {
            bytes: Vec::new(),
            limit: image.pfsc_start() as usize,
        };
        assert!(
            image
                .write(
                    &mut prefix,
                    true,
                    |_, _, _| panic!("no payload expected"),
                    || false
                )
                .is_err()
        );
        for index in [0, 8191, 8192, image.blocks] {
            assert_eq!(
                crate::input::le64(&prefix.bytes, PFSC_TABLE as usize + index as usize * 8),
                image.pfsc_start() + index * BLOCK as u64
            );
        }
    }

    #[test]
    fn directory_tail_always_fits_header_and_cancelled_publication_is_clean() {
        let mut bytes = vec![0; BLOCK - 32];
        dirent(&mut bytes, "x", 1, 2, true);
        assert_eq!(bytes.len(), BLOCK);
        assert_eq!(le32(&bytes, BLOCK - 20), 32);
        let root =
            std::env::temp_dir().join(format!("pkg-tools-inner-cancel-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let stop = std::cell::Cell::new(false);
        let image = InnerImage::new(&[entry("file", Some(BLOCK as u64 + 1))], 0).unwrap();
        let output = root.join("cancel.pfsc");
        assert_eq!(
            image
                .write_new(
                    &output,
                    |_, _, b| {
                        b.fill(0);
                        stop.set(true);
                        Ok(())
                    },
                    || stop.get()
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        // Destination appearing during streaming must win, never be replaced.
        assert_eq!(
            image
                .write_new(
                    &output,
                    |_, _, b| {
                        b.fill(0);
                        if !output.exists() {
                            fs::write(&output, b"existing")?;
                        }
                        Ok(())
                    },
                    || false
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&output).unwrap(), b"existing");
        fs::remove_file(output).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
