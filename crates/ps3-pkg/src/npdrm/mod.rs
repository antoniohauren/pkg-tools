mod crypto;
mod edat;
mod self_file;
mod sign;
#[cfg(test)]
pub(crate) mod tests;

use crate::Error;
use crypto::*;
use std::ops::Range;

pub(crate) const MAX_FILE: u64 = 256 * 1024 * 1024;
fn span(data: &[u8], offset: u64, size: u64) -> Result<Range<usize>, Error> {
    crate::range(offset, size, data.len() as u64)?;
    Ok(offset as usize..(offset + size) as usize)
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(crate::be32(&b[span(b, at as u64, 4)?], 0))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(crate::be64(&b[span(b, at as u64, 8)?], 0))
}
fn block(b: &[u8], at: usize) -> Result<[u8; 16], Error> {
    Ok(b[span(b, at as u64, 16)?].try_into().unwrap())
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_be_bytes());
}
fn check_cancel(cancel: &impl Fn() -> bool) -> Result<(), Error> {
    if cancel() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// A RAP has no embedded content ID. Its filename is a label; validation against
/// encrypted SELF/EDAT data happens during conversion.
pub struct Rap {
    key: [u8; 16],
}
impl Rap {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let rap = bytes
            .try_into()
            .map_err(|_| Error::Malformed("RAP must contain exactly 16 binary bytes"))?;
        Ok(Self { key: rap_key(rap) })
    }
}

pub(crate) use edat::convert as convert_edat;
pub(crate) use self_file::convert as convert_self;
pub use self_file::self_content_id;
