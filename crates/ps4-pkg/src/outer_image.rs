//! Signed S32, AES-XTS encrypted outer PFS, containing one raw PFSC inner image.
//!
//! Not a PKG writer. Caller supplies an already-derived image key (never logged),
//! not a passcode. No fixed authoring keys, licenses or container records are added.
//! Profile follows pinned LibOrbisPkg; see docs/fpkg-authoring-contract.md.

use crate::{
    crypto,
    inner_image::{self, BLOCK, InnerImage, check, dirent},
};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const INODE: usize = 0x2c8;
const REFS: u64 = BLOCK as u64 / 36;
const DIRECT: u64 = 12;
const FILE_INODE: u64 = BLOCK as u64 + 3 * INODE as u64;

/// Derive a legacy ready image key from explicit GP4-profile content ID and
/// 32 printable ASCII passcode bytes. Passcode is not hex-decoded. Returned key
/// is sensitive: keep it out of Debug/logs. No new-crypt transform or recovery.
pub fn legacy_image_key(content_id: &str, passcode: &str) -> io::Result<[u8; 32]> {
    if !crate::gp4::valid_content_id(content_id)
        || passcode.len() != 32
        || !passcode.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(invalid(
            "legacy image key requires valid content ID and 32 printable ASCII passcode bytes",
        ));
    }
    let id = content_id
        .as_bytes()
        .try_into()
        .map_err(|_| invalid("content ID length"))?;
    let passcode = passcode
        .as_bytes()
        .try_into()
        .map_err(|_| invalid("passcode length"))?;
    Ok(crypto::derived_key(id, passcode, 1))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn put32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}

/// Checked layout; payload and signature indexes stay on disk, not in RAM.
pub struct OuterImage<'a> {
    inner: &'a InnerImage,
    timestamp: i64,
    data_blocks: u64,
    leaves: u64,
    root: u64,
    data: u64,
    blocks: u64,
}

impl<'a> OuterImage<'a> {
    /// Legacy zero-seed profile, with direct/single/double signed references.
    /// Triple indirection is refused before I/O. Timestamp is explicit Unix seconds.
    pub fn new(inner: &'a InnerImage, timestamp: i64) -> io::Result<Self> {
        let data_blocks = inner.pfsc_size().div_ceil(BLOCK as u64);
        if data_blocks > DIRECT + REFS + REFS * REFS {
            return Err(invalid("outer PFS triple indirection is unsupported"));
        }
        let leaves = data_blocks.saturating_sub(DIRECT + REFS).div_ceil(REFS);
        let single = u64::from(data_blocks > DIRECT);
        // 0 header, 1 inodes, 2 superroot, 3 lookup, 4 clear reserved block.
        let root = 5 + single;
        let data = root + u64::from(leaves > 0) + leaves + 1; // uroot before payload
        let blocks = data + data_blocks;
        Ok(Self {
            inner,
            timestamp,
            data_blocks,
            leaves,
            root,
            data,
            blocks,
        })
    }

    pub fn pfs_size(&self) -> u64 {
        self.blocks * BLOCK as u64
    }

    fn inode(&self, directory: bool, links: u16, flags: u32, size: u64, logical: u64) -> Vec<u8> {
        let mut b = vec![0; INODE];
        b[..2].copy_from_slice(&(if directory { 0x416du16 } else { 0x816d }).to_le_bytes());
        b[2..4].copy_from_slice(&links.to_le_bytes());
        put32(&mut b, 4, flags | 0xc);
        put64(&mut b, 8, size);
        put64(&mut b, 16, logical);
        for p in [24, 32, 40, 48] {
            put64(&mut b, p, self.timestamp as u64);
        }
        put32(&mut b, 96, size.div_ceil(BLOCK as u64) as u32);
        b
    }

    fn file_ref(&self, index: u64) -> u64 {
        if index < DIRECT {
            FILE_INODE + 100 + index * 36
        } else if index < DIRECT + REFS {
            5 * BLOCK as u64 + (index - DIRECT) * 36
        } else {
            let i = index - DIRECT - REFS;
            (self.root + 1 + i / REFS) * BLOCK as u64 + (i % REFS) * 36
        }
    }

    /// Writes from offset zero to an empty readable/writable seekable scratch.
    /// Partial output must be discarded on failure. Inner callbacks have exactly
    /// InnerImage's stable-source contract. Work uses bounded 64-KiB buffers and
    /// multiple disk passes; output must not alias source files.
    pub fn write(
        &self,
        output: &mut (impl Read + Write + Seek),
        image_key: &[u8; 32],
        read: impl FnMut(usize, u64, &mut [u8]) -> io::Result<()>,
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        check(&mut cancelled)?;
        if output.stream_position()? != 0 {
            return Err(invalid("outer PFS output must start at zero"));
        }
        let mut b = vec![0; BLOCK];
        for _ in 0..self.data {
            check(&mut cancelled)?;
            output.write_all(&b)?;
        }
        self.inner.write(output, true, read, &mut cancelled)?;
        let end = output.stream_position()?;
        if end != self.pfs_size() {
            return Err(invalid("outer PFS payload length mismatch"));
        }

        // Construct all plaintext metadata before hashing its dependencies.
        put64(&mut b, 0, 1);
        put64(&mut b, 8, 20130315);
        b[0x1a] = 1;
        b[0x1c] = 0xd;
        put32(&mut b, 0x20, BLOCK as u32);
        put64(&mut b, 0x28, 1);
        put64(&mut b, 0x30, 4);
        put64(&mut b, 0x38, self.blocks);
        put64(&mut b, 0x40, 1);
        b[0x52] = 1;
        put64(&mut b, 0x58, BLOCK as u64);
        put64(&mut b, 0x60, BLOCK as u64);
        for p in [0x68, 0x70, 0x78, 0x80] {
            put64(&mut b, p, self.timestamp as u64);
        }
        put32(&mut b, 0xb0, 1);
        put32(&mut b, 0x36c, 1);
        output.seek(SeekFrom::Start(0))?;
        output.write_all(&b)?;
        let root_block = self.data - 1;
        let inodes = [
            self.inode(true, 1, 0x20000, BLOCK as u64, BLOCK as u64),
            self.inode(false, 1, 0x20000, 8, 8),
            self.inode(true, 3, 0, BLOCK as u64, BLOCK as u64),
            self.inode(false, 1, 1, self.inner.pfsc_size(), self.inner.pfs_size()),
        ];
        output.seek(SeekFrom::Start(BLOCK as u64))?;
        for inode in inodes {
            output.write_all(&inode)?;
        }
        let mut directory = Vec::new();
        dirent(&mut directory, "flat_path_table", 1, 2, true);
        dirent(&mut directory, "uroot", 2, 3, true);
        output.seek(SeekFrom::Start(2 * BLOCK as u64))?;
        output.write_all(&directory)?;
        let hash = b"/PFS_IMAGE.DAT"
            .iter()
            .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(*b)));
        output.seek(SeekFrom::Start(3 * BLOCK as u64))?;
        output.write_all(&hash.to_le_bytes())?;
        output.write_all(&3u32.to_le_bytes())?;
        directory.clear();
        for (name, number, kind) in [(".", 2, 4), ("..", 2, 5), ("pfs_image.dat", 3, 2)] {
            dirent(&mut directory, name, number, kind, true);
        }
        output.seek(SeekFrom::Start(root_block * BLOCK as u64))?;
        output.write_all(&directory)?;
        let signing = crypto::pfs_material(image_key, &[0; 16], 2);
        for (block, target) in [
            (2, BLOCK as u64 + 100),
            (3, BLOCK as u64 + INODE as u64 + 100),
            (root_block, BLOCK as u64 + 2 * INODE as u64 + 100),
        ] {
            sign(output, block, target, &signing, &mut b, &mut cancelled)?;
        }
        for i in 0..self.data_blocks {
            sign(
                output,
                self.data + i,
                self.file_ref(i),
                &signing,
                &mut b,
                &mut cancelled,
            )?;
        }
        if self.data_blocks > DIRECT {
            sign(
                output,
                5,
                FILE_INODE + 100 + DIRECT * 36,
                &signing,
                &mut b,
                &mut cancelled,
            )?;
        }
        for i in 0..self.leaves {
            sign(
                output,
                self.root + 1 + i,
                self.root * BLOCK as u64 + i * 36,
                &signing,
                &mut b,
                &mut cancelled,
            )?;
        }
        if self.leaves > 0 {
            sign(
                output,
                self.root,
                FILE_INODE + 100 + 13 * 36,
                &signing,
                &mut b,
                &mut cancelled,
            )?;
        }
        sign(output, 1, 0xb8, &signing, &mut b, &mut cancelled)?;
        // Header's HMAC/signature area is still zero. Coverage is exactly 0x5a0.
        output.seek(SeekFrom::Start(0))?;
        output.read_exact(&mut b[..0x5a0])?;
        let hash = crypto::hmac(&signing, &b[..0x5a0]);
        output.seek(SeekFrom::Start(0x380))?;
        output.write_all(&hash)?;
        let cipher = crypto::xts(&crypto::pfs_material(image_key, &[0; 16], 1));
        for block in 1..self.blocks {
            check(&mut cancelled)?;
            // Reference profile deliberately leaves reserved block 4 clear.
            if block == 4 {
                continue;
            }
            output.seek(SeekFrom::Start(block * BLOCK as u64))?;
            output.read_exact(&mut b)?;
            cipher.encrypt_area(
                &mut b,
                4096,
                u128::from(block * 16),
                xts_mode::get_tweak_default,
            );
            output.seek(SeekFrom::Start(block * BLOCK as u64))?;
            output.write_all(&b)?;
        }
        output.seek(SeekFrom::Start(self.pfs_size()))?;
        check(&mut cancelled)
    }

    /// Owner-only scratch and no-overwrite publication; only `.pfs` allowed.
    /// Destination parents must exist and remain stable. No second image scratch.
    pub fn write_new(
        &self,
        destination: &Path,
        image_key: &[u8; 32],
        read: impl FnMut(usize, u64, &mut [u8]) -> io::Result<()>,
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        self.write_new_checked(destination, image_key, read, &mut cancelled, || Ok(()))
    }

    pub(crate) fn write_new_checked(
        &self,
        destination: &Path,
        image_key: &[u8; 32],
        read: impl FnMut(usize, u64, &mut [u8]) -> io::Result<()>,
        mut cancelled: impl FnMut() -> bool,
        mut verify: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        check(&mut cancelled)?;
        if destination.extension().and_then(|s| s.to_str()) != Some("pfs") {
            return Err(invalid("outer image requires .pfs, never .pkg"));
        }
        inner_image::publish(destination, |file| {
            self.write(file, image_key, read, &mut cancelled)?;
            file.sync_all()?;
            verify()?;
            check(&mut cancelled)
        })
    }
}

fn sign(
    output: &mut (impl Read + Write + Seek),
    block: u64,
    target: u64,
    key: &[u8; 32],
    buffer: &mut [u8],
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<()> {
    check(cancelled)?;
    output.seek(SeekFrom::Start(block * BLOCK as u64))?;
    output.read_exact(buffer)?;
    let hash = crypto::hmac(key, buffer);
    output.seek(SeekFrom::Start(target))?;
    output.write_all(&hash)?;
    output.write_all(&(block as u32).to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        input::{Shared, le32, le64},
        pfs::{Pfs, PfsFile},
        pfsc::Pfsc,
    };
    use std::{
        cell::{Cell, RefCell},
        fs,
        io::Cursor,
        rc::Rc,
    };

    fn image() -> InnerImage {
        InnerImage::new(
            &[inner_image::Entry {
                path: "file".into(),
                size: Some(65537),
            }],
            123,
        )
        .unwrap()
    }
    fn fill(_: usize, offset: u64, b: &mut [u8]) -> io::Result<()> {
        for (i, v) in b.iter_mut().enumerate() {
            *v = ((offset + i as u64) % 251) as u8;
        }
        Ok(())
    }
    fn shared(bytes: Vec<u8>) -> Shared<Cursor<Vec<u8>>> {
        Shared {
            size: bytes.len() as u64,
            reader: Rc::new(RefCell::new(Cursor::new(bytes))),
        }
    }

    #[test]
    fn signed_encrypted_outer_reads_through_pfsc_to_inner() {
        let inner = image();
        let outer = OuterImage::new(&inner, 123).unwrap();
        let key = std::array::from_fn(|i| i as u8);
        let mut output = Cursor::new(Vec::new());
        outer.write(&mut output, &key, fill, || false).unwrap();
        assert_eq!(output.get_ref().len() as u64, outer.pfs_size());
        assert!(
            output.get_ref()[4 * BLOCK..5 * BLOCK]
                .iter()
                .all(|b| *b == 0)
        );
        let mut bytes = output.into_inner();
        assert!(Pfs::open(shared(bytes.clone()), Some(&[99; 32])).is_err());
        let mut pfs = Pfs::open(shared(bytes.clone()), Some(&key)).unwrap();
        let root = pfs.uroot().unwrap();
        let inode = pfs.inode(root).unwrap();
        let children = pfs.children(&inode).unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].0, "pfs_image.dat");
        let inode = pfs.inode(children[0].1).unwrap();
        assert_eq!(inode.size, inner.pfsc_size());
        assert_eq!(inode.compressed_size, inner.pfs_size());
        assert_eq!(inode.flags, 13);
        let pfsc = Pfsc::open(PfsFile { pfs, inode }).unwrap();
        let mut inner = Pfs::open(pfsc, None).unwrap();
        let root = inner.uroot().unwrap();
        let root = inner.inode(root).unwrap();
        let files = inner.children(&root).unwrap();
        let file = inner.inode(files[0].1).unwrap();
        let mut actual = vec![0; 65537];
        inner.read_file(&file, 0, &mut actual).unwrap();
        let mut expected = vec![0; actual.len()];
        fill(0, 0, &mut expected).unwrap();
        assert_eq!(actual, expected);
        bytes[0x100] ^= 1;
        assert!(Pfs::open(shared(bytes), Some(&key)).is_err());
    }

    #[test]
    fn plaintext_all_block_hmac_dependencies_and_corruption() {
        let inner = image();
        let outer = OuterImage::new(&inner, 0).unwrap();
        let key = [17; 32];
        let mut output = Cursor::new(Vec::new());
        outer.write(&mut output, &key, fill, || false).unwrap();
        let mut bytes = output.into_inner();
        let cipher = crypto::xts(&crypto::pfs_material(&key, &[0; 16], 1));
        for (i, b) in bytes.chunks_mut(BLOCK).enumerate().skip(1) {
            if i != 4 {
                cipher.decrypt_area(b, 4096, (i * 16) as u128, xts_mode::get_tweak_default);
            }
        }
        let signing = crypto::pfs_material(&key, &[0; 16], 2);
        let verify = |bytes: &[u8], target: usize| {
            let block = le32(bytes, target + 32) as usize;
            crypto::hmac(&signing, &bytes[block * BLOCK..(block + 1) * BLOCK])
                == bytes[target..target + 32]
        };
        assert!(verify(&bytes, 0xb8));
        for target in [BLOCK + 100, BLOCK + INODE + 100, BLOCK + 2 * INODE + 100] {
            assert!(verify(&bytes, target));
        }
        for i in 0..outer.data_blocks {
            assert!(verify(&bytes, outer.file_ref(i) as usize));
        }
        assert!(verify(&bytes, (FILE_INODE + 100 + DIRECT * 36) as usize));
        assert_eq!(le64(&bytes, 0x38), outer.blocks);
        bytes[outer.data as usize * BLOCK + 100] ^= 1;
        assert!(!verify(&bytes, outer.file_ref(0) as usize));
        bytes[BLOCK + INODE + 7] ^= 1;
        assert!(!verify(&bytes, 0xb8));
    }

    #[test]
    fn limits_double_layout_and_failure_publication() {
        let huge = InnerImage::new(
            &[inner_image::Entry {
                path: "huge".into(),
                size: Some((DIRECT + REFS + REFS * REFS) * BLOCK as u64),
            }],
            0,
        )
        .unwrap();
        assert!(OuterImage::new(&huge, 0).is_err());
        let double = InnerImage::new(
            &[inner_image::Entry {
                path: "large".into(),
                size: Some(4 * 1024 * 1024 * 1024 + 1),
            }],
            0,
        )
        .unwrap();
        let double = OuterImage::new(&double, 0).unwrap();
        assert!(double.leaves > 1);
        assert!(double.pfs_size() > u64::from(u32::MAX));
        assert_eq!(
            double.file_ref(DIRECT + REFS),
            (double.root + 1) * BLOCK as u64
        );
        let inner = image();
        let outer = OuterImage::new(&inner, 0).unwrap();
        let mut nonzero = Cursor::new(vec![0; 1]);
        nonzero.set_position(1);
        assert!(outer.write(&mut nonzero, &[0; 32], fill, || false).is_err());
        struct Short(Cursor<Vec<u8>>);
        impl Read for Short {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.0.read(b)
            }
        }
        impl Seek for Short {
            fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
                self.0.seek(p)
            }
        }
        impl Write for Short {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Ok(0)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            outer
                .write(&mut Short(Cursor::new(Vec::new())), &[0; 32], fill, || {
                    false
                })
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
        let root = std::env::temp_dir().join(format!("pkg-tools-outer-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let output = root.join("outer.pfs");
        assert!(
            outer
                .write_new(&root.join("bad.pkg"), &[0; 32], fill, || false)
                .is_err()
        );
        let stop = Cell::new(false);
        assert_eq!(
            outer
                .write_new(
                    &output,
                    &[0; 32],
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
        assert!(
            outer
                .write_new(
                    &output,
                    &[0; 32],
                    |_, _, _| Err(io::Error::other("source changed")),
                    || false
                )
                .is_err()
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        outer.write_new(&output, &[0; 32], fill, || false).unwrap();
        assert_eq!(
            outer
                .write_new(&output, &[0; 32], fill, || false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_file(&output).unwrap();
        assert_eq!(
            outer
                .write_new(
                    &output,
                    &[0; 32],
                    |i, o, b| {
                        if !output.exists() {
                            fs::write(&output, b"existing")?;
                        }
                        fill(i, o, b)
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
