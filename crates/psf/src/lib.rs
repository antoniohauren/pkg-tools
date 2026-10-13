//! Checked, byte-preserving PARAM.SFO parsing. No text decoding is forced.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
};

/// Inspection resource limits, not on-disk format limits.
pub const MAX_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 65_536;
pub const MAX_KEY_SIZE: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Malformed(&'static str),
    UnsupportedVersion(u32),
    LimitExceeded(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed SFO: {reason}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported SFO version: {v:#x}"),
            Self::LimitExceeded(reason) => write!(f, "SFO inspection limit exceeded: {reason}"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Binary(&'a [u8]),
    /// Bytes before the first NUL. Use `std::str::from_utf8` for strict decoding.
    Text(&'a [u8]),
    Integer(u32),
    Unknown {
        format: u16,
        bytes: &'a [u8],
    },
}

#[derive(Debug)]
pub struct Entry<'a> {
    pub key: &'a [u8],
    pub format: u16,
    pub value: Value<'a>,
    /// Exact used bytes, including text terminators.
    pub raw: &'a [u8],
    pub max_len: u32,
    pub padding: &'a [u8],
}

#[derive(Debug)]
pub struct Sfo<'a> {
    pub version: u32,
    pub entries: Vec<Entry<'a>>,
}

impl Sfo<'_> {
    pub fn get(&self, key: &[u8]) -> Option<&Entry<'_>> {
        self.entries.iter().find(|entry| entry.key == key)
    }
}

fn bytes(data: &[u8], offset: u64, len: u64) -> Result<&[u8], Error> {
    let end = offset
        .checked_add(len)
        .ok_or(Error::Malformed("range overflow"))?;
    if end > data.len() as u64 {
        return Err(Error::Malformed("range outside input"));
    }
    Ok(&data[offset as usize..end as usize])
}

fn u32le(data: &[u8], offset: u64) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}

/// Parse SFO 1.0 or 1.1, borrowing values and padding from `data`.
/// Duplicate/empty keys and unterminated text are malformed. Unknown formats
/// and non-UTF-8 keys/text are retained. Nonempty capacities must fit within
/// input and must not overlap. Resource limits are exposed as `MAX_*` constants.
pub fn parse(data: &[u8]) -> Result<Sfo<'_>, Error> {
    if data.len() > MAX_SIZE {
        return Err(Error::LimitExceeded("input exceeds 16 MiB"));
    }
    if bytes(data, 0, 4)? != b"\0PSF" {
        return Err(Error::Malformed("bad magic"));
    }
    let version = u32le(data, 4)?;
    if !matches!(version, 0x100 | 0x101) {
        return Err(Error::UnsupportedVersion(version));
    }
    let keys = u64::from(u32le(data, 8)?);
    let values = u64::from(u32le(data, 12)?);
    let count = u64::from(u32le(data, 16)?);
    let index_end = 20 + count * 16;
    if keys < index_end || values < keys || values > data.len() as u64 {
        return Err(Error::Malformed("invalid table layout"));
    }
    if count > MAX_ENTRIES as u64 {
        return Err(Error::LimitExceeded("more than 65536 entries"));
    }
    let key_table = bytes(data, keys, values - keys)?;
    let mut entries = Vec::with_capacity(count as usize);
    let mut seen = HashSet::with_capacity(count as usize);
    let mut ranges = BTreeMap::new();
    for i in 0..count {
        let record = bytes(data, 20 + i * 16, 16)?;
        let key_offset = u16::from_le_bytes([record[0], record[1]]) as usize;
        let format = u16::from_le_bytes([record[2], record[3]]);
        let len = u32le(record, 4)?;
        let max_len = u32le(record, 8)?;
        let offset = u64::from(u32le(record, 12)?);
        if len > max_len {
            return Err(Error::Malformed("value length exceeds capacity"));
        }
        let tail = key_table
            .get(key_offset..)
            .ok_or(Error::Malformed("key outside table"))?;
        let end = tail
            .iter()
            .take(MAX_KEY_SIZE + 1)
            .position(|b| *b == 0)
            .ok_or(if tail.len() > MAX_KEY_SIZE {
                Error::LimitExceeded("key exceeds 1024 bytes")
            } else {
                Error::Malformed("unterminated key")
            })?;
        let key = &tail[..end];
        if key.is_empty() || !seen.insert(key) {
            return Err(Error::Malformed("empty or duplicate key"));
        }
        let capacity = bytes(data, values + offset, u64::from(max_len))?;
        // Disallow aliasing to bound scanning and downstream output by input size.
        if max_len != 0 {
            let end = offset + u64::from(max_len);
            if ranges
                .range(..=offset)
                .next_back()
                .is_some_and(|(_, prev_end)| *prev_end > offset)
                || ranges
                    .range(offset..)
                    .next()
                    .is_some_and(|(next, _)| *next < end)
            {
                return Err(Error::Malformed("overlapping value capacities"));
            }
            ranges.insert(offset, end);
        }
        let (raw, padding) = capacity.split_at(len as usize);
        let value = match format {
            0x0004 => Value::Binary(raw),
            0x0204 => {
                let end = raw
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or(Error::Malformed("unterminated text"))?;
                Value::Text(&raw[..end])
            }
            0x0404 => {
                if len != 4 {
                    return Err(Error::Malformed("integer is not 4 bytes"));
                }
                Value::Integer(u32le(raw, 0)?)
            }
            _ => Value::Unknown { format, bytes: raw },
        };
        entries.push(Entry {
            key,
            format,
            value,
            raw,
            max_len,
            padding,
        });
    }
    Ok(Sfo { version, entries })
}
