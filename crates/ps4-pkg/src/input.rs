use crate::{Error, range};
use std::{
    cell::RefCell,
    io::{Read, Seek, SeekFrom},
    rc::Rc,
};

pub(crate) trait ReadAt {
    fn len(&self) -> u64;
    fn read_at(&mut self, offset: u64, data: &mut [u8]) -> Result<(), Error>;
}

pub(crate) struct Shared<R> {
    pub reader: Rc<RefCell<R>>,
    pub size: u64,
}
impl<R: Read + Seek> ReadAt for Shared<R> {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&mut self, offset: u64, data: &mut [u8]) -> Result<(), Error> {
        range(offset, data.len() as u64, self.size)?;
        let mut r = self.reader.borrow_mut();
        r.seek(SeekFrom::Start(offset))?;
        r.read_exact(data)?;
        Ok(())
    }
}

pub(crate) struct Region<T> {
    pub source: T,
    pub offset: u64,
    pub size: u64,
}
impl<T: ReadAt> ReadAt for Region<T> {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&mut self, offset: u64, data: &mut [u8]) -> Result<(), Error> {
        range(offset, data.len() as u64, self.size)?;
        self.source.read_at(
            self.offset
                .checked_add(offset)
                .ok_or(Error::Malformed("offset overflow"))?,
            data,
        )
    }
}

pub(crate) fn le16(b: &[u8], n: usize) -> u16 {
    u16::from_le_bytes(b[n..n + 2].try_into().unwrap())
}
pub(crate) fn le32(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(b[n..n + 4].try_into().unwrap())
}
pub(crate) fn le64(b: &[u8], n: usize) -> u64 {
    u64::from_le_bytes(b[n..n + 8].try_into().unwrap())
}
