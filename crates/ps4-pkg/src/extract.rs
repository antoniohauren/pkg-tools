use crate::{
    Entry, Error, Package, crypto,
    input::{ReadAt, Region, Shared},
    pfs::{Inode, Pfs, PfsFile},
    pfsc::Pfsc,
};
use aes::{
    Aes128,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    io::{self, Read, Seek, SeekFrom},
    path::Path,
    rc::Rc,
};

type Inner<R> = Pfs<Pfsc<PfsFile<Region<Shared<R>>>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
}

#[derive(Debug)]
pub struct FileEntry {
    path: String,
    size: u64,
    kind: FileKind,
    source: Source,
}
impl FileEntry {
    /// Portable, slash-separated path relative to the application root.
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn kind(&self) -> FileKind {
        self.kind
    }
}
#[derive(Debug)]
enum Source {
    Pfs(Inode),
    Container(Entry),
    Directory,
}

/// Decoded application tree, including container metadata under `sce_sys`.
/// Payload/index reads use fixed buffers; tree metadata is bounded separately.
pub struct Game<R> {
    inner: Inner<R>,
    container: Shared<R>,
    dk3: [u8; 32],
    entries: Vec<FileEntry>,
}

pub(crate) fn component(name: &str) -> Result<(), Error> {
    // ASCII avoids filesystem-specific Unicode normalization/case-fold aliases.
    if !name.is_ascii() {
        return Err(Error::Unsupported("non-ASCII extraction path"));
    }
    if !pkg_fs::valid_component(name) {
        return Err(Error::UnsafePath(name.to_owned()));
    }
    Ok(())
}

fn metadata_name(id: u32) -> Option<String> {
    let fixed = match id {
        0x1000 => "param.sfo",
        0x1001 => "playgo-chunk.dat",
        0x1002 => "playgo-chunk.sha",
        0x1003 => "playgo-manifest.xml",
        0x1004 => "pronunciation.xml",
        0x1005 => "pronunciation.sig",
        0x1006 => "pic1.png",
        0x1007 => "pubtoolinfo.dat",
        0x1008 => "app/playgo-chunk.dat",
        0x1009 => "app/playgo-chunk.sha",
        0x100a => "app/playgo-manifest.xml",
        0x100b => "shareparam.json",
        0x100c => "shareoverlayimage.png",
        0x100d => "save_data.png",
        0x100e => "shareprivacyguardimage.png",
        0x1200 => "icon0.png",
        0x1220 => "pic0.png",
        0x1240 => "snd0.at9",
        0x1260 => "changeinfo/changeinfo.xml",
        0x1280 => "icon0.dds",
        0x12a0 => "pic0.dds",
        0x12c0 => "pic1.dds",
        _ => "",
    };
    if !fixed.is_empty() {
        return Some(fixed.to_owned());
    }
    for (start, prefix, suffix) in [
        (0x1201, "icon0_", "png"),
        (0x1241, "pic1_", "png"),
        (0x1261, "changeinfo/changeinfo_", "xml"),
        (0x1281, "icon0_", "dds"),
        (0x12c1, "pic1_", "dds"),
    ] {
        if (start..start + 31).contains(&id) {
            return Some(format!("{prefix}{:02}.{suffix}", id - start));
        }
    }
    if (0x1400..=0x1463).contains(&id) {
        return Some(format!("trophy/trophy{:02}.trp", id - 0x1400));
    }
    if (0x1600..0x1800).contains(&id) && id & 15 < 10 {
        let group = (id - 0x1600) / 16;
        let image = (id & 15) + 1;
        return Some(if group == 0 {
            format!("keymap_rp/{image:03}.png")
        } else {
            format!("keymap_rp/{:02}/{image:03}.png", group - 1)
        });
    }
    None
}

struct Tree {
    entries: BTreeMap<String, FileEntry>,
    bytes: usize,
}
impl Tree {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            bytes: 0,
        }
    }
    fn add(&mut self, path: String, source: Source) -> Result<(), Error> {
        if path.len() > 4096 || path.split('/').count() > 128 {
            return Err(Error::LimitExceeded("path length/depth"));
        }
        for part in path.split('/') {
            component(part)?;
        }
        if path.eq_ignore_ascii_case(".pkg-tools-incomplete") {
            return Err(Error::UnsafePath(path));
        }
        let key = path.to_ascii_lowercase();
        if let Some(old) = self.entries.get(&key) {
            if old.path == path
                && matches!(source, Source::Directory)
                && old.kind == FileKind::Directory
            {
                return Ok(());
            }
            return Err(Error::UnsafePath(path));
        }
        if let Some((parent, _)) = path.rsplit_once('/') {
            self.add(parent.to_owned(), Source::Directory)?;
        }
        self.bytes += path.len();
        if self.entries.len() >= 1_000_000 || self.bytes > 64 * 1024 * 1024 {
            return Err(Error::LimitExceeded("application tree metadata"));
        }
        let (kind, size) = match &source {
            Source::Directory => (FileKind::Directory, 0),
            Source::Pfs(i) => (FileKind::File, i.size),
            Source::Container(e) => (FileKind::File, u64::from(e.size)),
        };
        self.entries.insert(
            key,
            FileEntry {
                path,
                size,
                kind,
                source,
            },
        );
        Ok(())
    }
}

impl<R: Read + Seek> Package<R> {
    /// Recover public fake-package keys and enumerate the supported nested PFS.
    /// Does not modify the source or authenticate every payload block.
    pub fn open_game(mut self) -> Result<Game<R>, Error> {
        if self.header.content_type != 0x1a || self.header.content_flags & 0x0100_0000 != 0 {
            return Err(Error::Unsupported(
                "extraction requires a GD base/full update (no delta/DLC/theme)",
            ));
        }
        if self.header.pfs_flags & 0x8000_0000_0000_0000 == 0 {
            return Err(Error::Unsupported("non-nested PFS"));
        }
        let find =
            |id| {
                self.entries.iter().find(|e| e.id == id).cloned().ok_or(
                    Error::DecryptionUnavailable {
                        entry_id: id,
                        key_index: 3,
                    },
                )
            };
        let keys = find(0x10)?;
        let image = find(0x20)?;
        if keys.encrypted() || keys.size != 2048 || image.size != 256 {
            return Err(Error::Malformed("fake-key entry layout"));
        }
        if !image.encrypted() || image.key_index() != 3 {
            return Err(Error::DecryptionUnavailable {
                entry_id: 0x20,
                key_index: image.key_index(),
            });
        }
        if image.flags1 & 0x1000_0000 != 0 {
            return Err(Error::Unsupported("new container encryption algorithm"));
        }
        let mut key_bytes = [0; 2048];
        let mut image_bytes = [0; 256];
        self.reader.seek(SeekFrom::Start(u64::from(keys.offset)))?;
        self.reader.read_exact(&mut key_bytes)?;
        self.reader.seek(SeekFrom::Start(u64::from(image.offset)))?;
        self.reader.read_exact(&mut image_bytes)?;
        let (dk3, ekpfs) = crypto::recover(&key_bytes, &mut image_bytes, &image)?;
        let reader = Rc::new(RefCell::new(self.reader));
        let shared = || Shared {
            reader: Rc::clone(&reader),
            size: self.header.package_size,
        };
        let mut outer = Pfs::open(
            Region {
                source: shared(),
                offset: self.header.pfs_offset,
                size: self.header.pfs_size,
            },
            Some(&ekpfs),
        )?;
        let root = outer.uroot()?;
        let root = outer.inode(root)?;
        let children = outer.children(&root)?;
        let images: Vec<_> = children
            .iter()
            .filter(|(n, _, dir)| n == "pfs_image.dat" && !dir)
            .collect();
        if images.len() != 1 {
            return Err(Error::Malformed("outer PFS requires one pfs_image.dat"));
        }
        let inode = outer.inode(images[0].1)?;
        if inode.mode & 0xf000 != 0x8000 {
            return Err(Error::Malformed("outer image inode type"));
        }
        let mut inner = Pfs::open(Pfsc::open(PfsFile { pfs: outer, inode })?, None)?;
        let root = inner.uroot()?;
        let mut pending = vec![(String::new(), root)];
        let mut seen = HashSet::new();
        let mut tree = Tree::new();
        while let Some((path, number)) = pending.pop() {
            if !seen.insert(number) {
                return Err(Error::Malformed("PFS directory cycle/alias"));
            }
            let inode = inner.inode(number)?;
            let children = inner.children(&inode)?;
            let mut names = HashSet::new();
            for (name, number, dir) in children {
                if !names.insert(name.to_ascii_lowercase()) {
                    return Err(Error::UnsafePath(name));
                }
                let path = if path.is_empty() {
                    name
                } else {
                    format!("{path}/{name}")
                };
                let inode = inner.inode(number)?;
                if dir != (inode.mode & 0xf000 == 0x4000) {
                    return Err(Error::Malformed("PFS dirent/inode type mismatch"));
                }
                if dir {
                    tree.add(path.clone(), Source::Directory)?;
                    pending.push((path, number));
                } else {
                    if inode.size != inode.compressed_size || inode.flags & 1 != 0 {
                        return Err(Error::Unsupported("per-file PFS compression"));
                    }
                    tree.add(path, Source::Pfs(inode))?;
                }
            }
        }
        for e in self.entries {
            if let Some(name) = metadata_name(e.id) {
                if e.encrypted() && e.flags1 & 0x1000_0000 != 0 {
                    return Err(Error::Unsupported("new container encryption algorithm"));
                }
                if e.encrypted() && e.key_index() != 3 {
                    return Err(Error::DecryptionUnavailable {
                        entry_id: e.id,
                        key_index: e.key_index(),
                    });
                }
                tree.add(format!("sce_sys/{name}"), Source::Container(e))?;
            } else if e.id >= 0x1000 {
                return Err(Error::Unsupported("unknown application metadata ID"));
            }
        }
        Ok(Game {
            inner,
            container: shared(),
            dk3,
            entries: tree.entries.into_values().collect(),
        })
    }
}

impl<R: Read + Seek> Game<R> {
    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }
    /// Borrow one entry by enumeration index. Files implement streaming `Read`/`Seek`.
    pub fn read_entry(&mut self, index: usize) -> Result<EntryReader<'_, R>, Error> {
        let entry = self
            .entries
            .get(index)
            .ok_or(Error::Malformed("application entry index"))?;
        if entry.kind != FileKind::File {
            return Err(Error::Unsupported("cannot read directory as file"));
        }
        Ok(EntryReader {
            game: self,
            index,
            position: 0,
        })
    }
    /// Create a new output directory; never merge or overwrite. On failure the
    /// error names the incomplete tree and its marker remains for interruption detection.
    pub fn extract(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.extract_with_cancel(path, || false)
    }

    /// Like `extract`, checking cancellation before creating output, between entries,
    /// and between 64 KiB chunks. Cancelled partial output retains its marker.
    pub fn extract_with_cancel(
        &mut self,
        path: impl AsRef<Path>,
        cancelled: impl FnMut() -> bool,
    ) -> Result<(), Error> {
        self.extract_with_progress(path, cancelled, |_, _| {})
    }

    /// Report output bytes written and total decoded file bytes, initially and
    /// after each chunk. Completion still requires a successful return value.
    pub fn extract_with_progress(
        &mut self,
        path: impl AsRef<Path>,
        cancelled: impl FnMut() -> bool,
        progress: impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        #[cfg(unix)]
        {
            disk::extract(self, path.as_ref(), cancelled, progress)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, cancelled, progress);
            Err(Error::Unsupported(
                "safe disk extraction currently requires Unix",
            ))
        }
    }
}

pub struct EntryReader<'a, R> {
    game: &'a mut Game<R>,
    index: usize,
    position: u64,
}
impl<R: Read + Seek> EntryReader<'_, R> {
    fn read_bytes(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        let e = &self.game.entries[self.index];
        let n = (e.size - self.position).min(data.len() as u64).min(65536) as usize;
        if n == 0 {
            return Ok(0);
        }
        match &e.source {
            Source::Pfs(inode) => {
                self.game
                    .inner
                    .read_file(inode, self.position, &mut data[..n])?
            }
            Source::Container(entry) => read_container(
                &mut self.game.container,
                entry,
                &self.game.dk3,
                self.position,
                &mut data[..n],
            )?,
            Source::Directory => unreachable!(),
        }
        self.position += n as u64;
        Ok(n)
    }
}
impl<R: Read + Seek> Read for EntryReader<'_, R> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.read_bytes(data).map_err(|e| match e {
            Error::Io(e) => e,
            Error::Unsupported(_) => io::Error::new(io::ErrorKind::Unsupported, e),
            _ => io::Error::new(io::ErrorKind::InvalidData, e),
        })
    }
}
impl<R: Read + Seek> Seek for EntryReader<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.game.entries[self.index].size;
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

fn read_container(
    source: &mut impl ReadAt,
    e: &Entry,
    dk3: &[u8; 32],
    mut offset: u64,
    mut data: &mut [u8],
) -> Result<(), Error> {
    crate::range(offset, data.len() as u64, u64::from(e.size))?;
    if !e.encrypted() {
        return source.read_at(u64::from(e.offset) + offset, data);
    }
    let material = crypto::entry_material(e, dk3);
    let mut buf = [0; 65536];
    while !data.is_empty() {
        let start = offset / 16 * 16;
        let skip = (offset - start) as usize;
        let full_end = u64::from(e.size) / 16 * 16;
        let mut iv = [0; 16];
        if start == 0 {
            iv.copy_from_slice(&material[..16]);
        } else {
            source.read_at(u64::from(e.offset) + start - 16, &mut iv)?;
        }
        if start >= full_end {
            // Format tail is CFB over the previous CBC ciphertext, not padded storage.
            let aes = Aes128::new_from_slice(&material[16..]).unwrap();
            let mut stream = iv.into();
            aes.encrypt_block(&mut stream);
            let n = data.len();
            source.read_at(u64::from(e.offset) + offset, data)?;
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= stream[skip + i];
            }
            offset += n as u64;
            data = &mut data[n..];
        } else {
            let want = (data.len() + skip).div_ceil(16) * 16;
            let stored = want.min(buf.len()).min((full_end - start) as usize);
            source.read_at(u64::from(e.offset) + start, &mut buf[..stored])?;
            crypto::cbc_decrypt(&mut buf[..stored], &material[16..], &iv)?;
            let n = data.len().min(stored - skip);
            data[..n].copy_from_slice(&buf[skip..skip + n]);
            offset += n as u64;
            data = &mut data[n..];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn portable_paths_and_tree_collisions() {
        for name in [
            "", ".", "..", "../a", "/root", "C:foo", "a\\b", "a\0b", "NUL.txt", "COM1", "end.",
            "end ", "é",
        ] {
            assert!(component(name).is_err(), "{name:?}");
        }
        let entry = || {
            Source::Container(Entry {
                id: 0x1000,
                name_offset: 0,
                flags1: 0,
                flags2: 0,
                offset: 0,
                size: 0,
            })
        };
        for (first, second) in [
            ("Foo", "foo"),
            ("a", "a/b"),
            ("a/b", "a"),
            ("Dir/a", "dir/b"),
            ("same", "same"),
        ] {
            let mut tree = Tree::new();
            tree.add(first.into(), entry()).unwrap();
            assert!(tree.add(second.into(), entry()).is_err());
        }
        assert!(
            Tree::new()
                .add(".PKG-TOOLS-INCOMPLETE".into(), entry())
                .is_err()
        );
    }

    #[test]
    fn encrypted_entry_partial_tail_and_random_reads() {
        // Independent OpenSSL CBC + ECB/CFB-tail vector; no bytes beyond logical size exist.
        let ciphertext =
            "92d2c85a702a15974ab5e0475c558ae355cedbcb4b562d36bf917874cfc1f5132e3d7f6f31";
        let bytes: Vec<u8> = (0..ciphertext.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&ciphertext[i..i + 2], 16).unwrap())
            .collect();
        let mut source = Shared {
            reader: Rc::new(RefCell::new(io::Cursor::new(bytes))),
            size: 37,
        };
        let e = Entry {
            id: 0x1000,
            name_offset: 0,
            flags1: 0x80000000,
            flags2: 0x3000,
            offset: 0,
            size: 37,
        };
        for start in 0..37 {
            for len in 0..=37 - start {
                let mut out = vec![0; len];
                read_container(&mut source, &e, &[0x24; 32], start as u64, &mut out).unwrap();
                assert_eq!(out, (start as u8..(start + len) as u8).collect::<Vec<_>>());
            }
        }
    }
}

#[cfg(unix)]
mod disk {
    use super::*;
    use std::io::Write;
    pub(super) fn extract<R: Read + Seek>(
        game: &mut Game<R>,
        path: &Path,
        mut cancelled: impl FnMut() -> bool,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        let total = game.entries.iter().try_fold(0u64, |sum, entry| {
            sum.checked_add(entry.size)
                .ok_or(Error::LimitExceeded("total extracted size"))
        })?;
        let mut completed = 0;
        progress(0, total);
        let output = pkg_fs::Output::create(path)?;
        let result = (|| -> Result<(), Error> {
            output.mark_incomplete()?;
            let mut buffer = [0; 65536];
            for index in 0..game.entries.len() {
                if cancelled() {
                    return Err(Error::Cancelled);
                }
                let e = &game.entries[index];
                if e.kind == FileKind::Directory {
                    output.create_directory(&e.path)?;
                } else {
                    let size = e.size;
                    let mut out = output.create_file(&e.path)?;
                    let mut reader = game.read_entry(index)?;
                    let mut written = 0;
                    loop {
                        if cancelled() {
                            return Err(Error::Cancelled);
                        }
                        let count = match reader.read(&mut buffer) {
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            result => result?,
                        };
                        if count == 0 {
                            break;
                        }
                        out.write_all(&buffer[..count])?;
                        written += count as u64;
                        completed += count as u64;
                        progress(completed, total);
                    }
                    if written != size {
                        return Err(Error::Malformed("short entry read"));
                    }
                    out.flush()?;
                }
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
