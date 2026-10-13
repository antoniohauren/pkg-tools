use crate::{
    Error, crypto,
    input::{ReadAt, le16, le32, le64},
    range,
};
use aes::Aes128;
use xts_mode::Xts128;

pub(crate) const BLOCK: u64 = 65536;
const REFS: u64 = BLOCK / 36;

#[derive(Clone, Debug)]
pub(crate) struct Inode {
    pub mode: u16,
    pub size: u64,
    pub compressed_size: u64,
    pub flags: u32,
    blocks: u32,
    refs: [u32; 17],
}

pub(crate) struct Pfs<T> {
    source: T,
    signed: bool,
    inodes: u64,
    inode_blocks: u64,
    cipher: Option<Xts128<Aes128>>,
    cache: Vec<u8>,
    cached: Option<u64>,
}

impl<T: ReadAt> Pfs<T> {
    pub fn open(mut source: T, key: Option<&[u8; 32]>) -> Result<Self, Error> {
        let mut h = [0; 0x400];
        source.read_at(0, &mut h)?;
        if le64(&h, 0) != 1 {
            return Err(Error::Unsupported("PFS version"));
        }
        if le64(&h, 8) != 20130315 {
            return Err(Error::Malformed("PFS magic"));
        }
        let mode = le16(&h, 0x1c);
        if mode & !0xd != 0 {
            return Err(Error::Unsupported("PFS mode (64-bit or unknown flags)"));
        }
        if le32(&h, 0x20) != BLOCK as u32 {
            return Err(Error::Unsupported("PFS block size"));
        }
        if !source.len().is_multiple_of(BLOCK) {
            return Err(Error::Malformed("unaligned PFS image"));
        }
        let signed = mode & 1 != 0;
        if signed && let Some(key) = key {
            let signing = crypto::pfs_material(key, &h[0x370..0x380], 2);
            let mut covered = [0; 0x5a0];
            covered[..0x380].copy_from_slice(&h[..0x380]);
            if crypto::hmac(&signing, &covered) != h[0x380..0x3a0] {
                return Err(Error::Malformed("PFS header HMAC mismatch"));
            }
        }
        let inode_blocks = le64(&h, 0x40);
        let inodes = le64(&h, 0x30);
        let per_block = BLOCK / if signed { 0x2c8 } else { 0xa8 };
        if inodes == 0
            || inode_blocks == 0
            || inode_blocks >= source.len() / BLOCK
            || inodes.div_ceil(per_block) > inode_blocks
        {
            return Err(Error::Malformed("PFS inode table range"));
        }
        if inodes > 1_000_000 {
            return Err(Error::LimitExceeded("more than one million PFS inodes"));
        }
        let cipher = if mode & 4 != 0 {
            let key = key.ok_or(Error::Unsupported("encrypted inner PFS"))?;
            Some(crypto::xts(&crypto::pfs_material(key, &h[0x370..0x380], 1)))
        } else {
            None
        };
        Ok(Self {
            source,
            signed,
            inodes,
            inode_blocks,
            cipher,
            cache: vec![0; BLOCK as usize],
            cached: None,
        })
    }

    pub fn inode(&mut self, number: u32) -> Result<Inode, Error> {
        if u64::from(number) >= self.inodes {
            return Err(Error::Malformed("PFS inode number"));
        }
        let width = if self.signed { 0x2c8 } else { 0xa8 };
        let per_block = BLOCK / width;
        let number = u64::from(number);
        let offset = (1 + number / per_block) * BLOCK + (number % per_block) * width;
        let mut b = [0; 0x2c8];
        self.read_at(offset, &mut b[..width as usize])?;
        let mut refs = [0; 17];
        for (i, r) in refs.iter_mut().enumerate() {
            *r = le32(
                &b,
                if self.signed {
                    100 + i * 36 + 32
                } else {
                    100 + i * 4
                },
            );
        }
        let inode = Inode {
            mode: le16(&b, 0),
            flags: le32(&b, 4),
            size: le64(&b, 8),
            compressed_size: le64(&b, 16),
            blocks: le32(&b, 96),
            refs,
        };
        if inode.size > u64::from(inode.blocks) * BLOCK {
            return Err(Error::Malformed("PFS file exceeds allocated blocks"));
        }
        if !matches!(inode.mode & 0xf000, 0x4000 | 0x8000) {
            return Err(Error::Unsupported("PFS symlink or special inode"));
        }
        if inode.blocks > 1 && inode.refs[1] != u32::MAX {
            if !self.signed {
                return Err(Error::Unsupported("fragmented unsigned PFS"));
            }
            if u64::from(inode.blocks) > 12 + REFS + REFS * REFS {
                return Err(Error::Unsupported("PFS triple indirection"));
            }
        } else if inode.blocks > 0 {
            self.block(inode.refs[0])?;
            let last = inode.refs[0]
                .checked_add(inode.blocks - 1)
                .ok_or(Error::Malformed("PFS extent overflow"))?;
            self.block(last)?;
        }
        Ok(inode)
    }

    fn block(&self, block: u32) -> Result<u64, Error> {
        if u64::from(block) <= self.inode_blocks || u64::from(block) >= self.source.len() / BLOCK {
            return Err(Error::Malformed("PFS data block range"));
        }
        Ok(u64::from(block) * BLOCK)
    }

    fn indirect(&mut self, block: u32, index: u64) -> Result<u32, Error> {
        if index >= REFS {
            return Err(Error::Malformed("PFS indirect index"));
        }
        let offset = self.block(block)? + index * 36 + 32;
        let mut b = [0; 4];
        self.read_at(offset, &mut b)?;
        Ok(le32(&b, 0))
    }

    fn mapped(&mut self, inode: &Inode, index: u64) -> Result<u64, Error> {
        if index >= u64::from(inode.blocks) {
            return Err(Error::Malformed("PFS file block index"));
        }
        let block = if inode.blocks <= 1 || inode.refs[1] == u32::MAX {
            inode.refs[0]
                .checked_add(index as u32)
                .ok_or(Error::Malformed("PFS extent overflow"))?
        } else if index < 12 {
            inode.refs[index as usize]
        } else if index < 12 + REFS {
            self.indirect(inode.refs[12], index - 12)?
        } else {
            let i = index - 12 - REFS;
            let indirect = self.indirect(inode.refs[13], i / REFS)?;
            self.indirect(indirect, i % REFS)?
        };
        self.block(block)
    }

    pub fn read_file(
        &mut self,
        inode: &Inode,
        mut offset: u64,
        mut data: &mut [u8],
    ) -> Result<(), Error> {
        range(offset, data.len() as u64, inode.size)?;
        while !data.is_empty() {
            let within = offset % BLOCK;
            let n = data.len().min((BLOCK - within) as usize);
            let pos = self.mapped(inode, offset / BLOCK)? + within;
            self.read_at(pos, &mut data[..n])?;
            offset += n as u64;
            data = &mut data[n..];
        }
        Ok(())
    }

    pub fn children(&mut self, inode: &Inode) -> Result<Vec<(String, u32, bool)>, Error> {
        if inode.mode & 0xf000 != 0x4000 {
            return Err(Error::Malformed("PFS directory inode type"));
        }
        if inode.size > 64 * 1024 * 1024 {
            return Err(Error::LimitExceeded("PFS directory larger than 64 MiB"));
        }
        let mut result = Vec::new();
        let mut buf = vec![0; BLOCK as usize];
        for block in 0..inode.size.div_ceil(BLOCK) {
            let n = (inode.size - block * BLOCK).min(BLOCK) as usize;
            self.read_file(inode, block * BLOCK, &mut buf[..n])?;
            let mut pos = 0;
            while pos < n {
                if n - pos < 16 {
                    return Err(Error::Malformed("truncated PFS dirent"));
                }
                let b = &buf[pos..n];
                let ino = le32(b, 0);
                let kind = le32(b, 4);
                let name_len = le32(b, 8) as usize;
                let size = le32(b, 12) as usize;
                if size == 0 {
                    if b.iter().any(|v| *v != 0) {
                        return Err(Error::Malformed("nonzero PFS directory tail"));
                    }
                    break;
                }
                if size < 24
                    || size > b.len()
                    || !size.is_multiple_of(8)
                    || name_len == 0
                    || name_len > 255
                    || name_len + 17 > size
                    || b[16 + name_len] != 0
                {
                    return Err(Error::Malformed("PFS dirent size/name"));
                }
                let name = std::str::from_utf8(&b[16..16 + name_len])
                    .map_err(|_| Error::Unsupported("non-UTF-8 PFS name"))?;
                match kind {
                    4 if name == "." => {}
                    5 if name == ".." => {}
                    2 | 3 => {
                        crate::extract::component(name)?;
                        if result.len() >= 1_000_000 {
                            return Err(Error::LimitExceeded("PFS directory entry count"));
                        }
                        result.push((name.to_owned(), ino, kind == 3));
                    }
                    _ => return Err(Error::Unsupported("PFS directory entry kind")),
                }
                pos += size;
            }
        }
        Ok(result)
    }

    pub fn uroot(&mut self) -> Result<u32, Error> {
        let root = self.inode(0)?;
        let children = self.children(&root)?;
        let roots: Vec<_> = children
            .iter()
            .filter(|(name, _, dir)| name == "uroot" && *dir)
            .collect();
        if roots.len() != 1 {
            return Err(Error::Malformed("PFS requires one uroot directory"));
        }
        Ok(roots[0].1)
    }
}

impl<T: ReadAt> ReadAt for Pfs<T> {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_at(&mut self, mut offset: u64, mut data: &mut [u8]) -> Result<(), Error> {
        range(offset, data.len() as u64, self.len())?;
        let Some(cipher) = &self.cipher else {
            return self.source.read_at(offset, data);
        };
        while !data.is_empty() {
            let block = offset / BLOCK;
            let within = (offset % BLOCK) as usize;
            let n = data.len().min(BLOCK as usize - within);
            if self.cached != Some(block) {
                self.cached = None;
                self.source.read_at(block * BLOCK, &mut self.cache)?;
                if block != 0 {
                    cipher.decrypt_area(
                        &mut self.cache,
                        4096,
                        u128::from(block * 16),
                        xts_mode::get_tweak_default,
                    );
                }
                self.cached = Some(block);
            }
            data[..n].copy_from_slice(&self.cache[within..within + n]);
            data = &mut data[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

pub(crate) struct PfsFile<T> {
    pub pfs: Pfs<T>,
    pub inode: Inode,
}
impl<T: ReadAt> ReadAt for PfsFile<T> {
    fn len(&self) -> u64 {
        self.inode.size
    }
    fn read_at(&mut self, offset: u64, data: &mut [u8]) -> Result<(), Error> {
        self.pfs.read_file(&self.inode, offset, data)
    }
}
