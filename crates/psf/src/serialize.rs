use std::collections::HashSet;

use crate::{Error, MAX_ENTRIES, MAX_KEY_SIZE, MAX_SIZE, Sfo, value_from_raw};

const HEADER_SIZE: usize = 20;
const INDEX_SIZE: usize = 16;
const ALIGNMENT: usize = 4;

fn add_size(size: usize, amount: usize) -> Result<usize, Error> {
    size.checked_add(amount)
        .filter(|size| *size <= MAX_SIZE)
        .ok_or(Error::LimitExceeded("serialized output exceeds 16 MiB"))
}

fn align(size: usize) -> Result<usize, Error> {
    add_size(size, (ALIGNMENT - size % ALIGNMENT) % ALIGNMENT)
}

/// Serialize SFO 1.1 into a new buffer, subject to the parser's `MAX_*` limits.
///
/// Retains entry order, keys, formats, raw used bytes, capacities and padding.
/// `raw` is authoritative: `value` must match its interpretation for `format`,
/// and `raw.len() + padding.len()` must equal `max_len`. Invalid or inconsistent
/// models are rejected, including empty/duplicate/NUL-containing keys.
///
/// Tables and each value start are four-byte aligned, with zero-filled layout
/// gaps. Original offsets, gaps and trailing bytes are not retained. SFO 1.0
/// remains readable but must be explicitly changed to version 1.1 to serialize.
pub fn serialize(sfo: &Sfo<'_>) -> Result<Vec<u8>, Error> {
    if sfo.version != 0x101 {
        return Err(Error::UnsupportedVersion(sfo.version));
    }
    if sfo.entries.len() > MAX_ENTRIES {
        return Err(Error::LimitExceeded("more than 65536 entries"));
    }
    let keys = HEADER_SIZE + sfo.entries.len() * INDEX_SIZE;
    let mut key_len = 0;
    let mut data_len = 0;
    let mut seen = HashSet::with_capacity(sfo.entries.len());
    for entry in &sfo.entries {
        if entry.key.is_empty() || entry.key.contains(&0) || !seen.insert(entry.key) {
            return Err(Error::Malformed("empty, duplicate or NUL-containing key"));
        }
        if entry.key.len() > MAX_KEY_SIZE {
            return Err(Error::LimitExceeded("key exceeds 1024 bytes"));
        }
        u16::try_from(key_len).map_err(|_| Error::LimitExceeded("key offset exceeds u16"))?;
        key_len = add_size(add_size(key_len, entry.key.len())?, 1)?;
        let capacity = add_size(entry.raw.len(), entry.padding.len())?;
        if capacity as u64 != u64::from(entry.max_len) {
            return Err(Error::Malformed(
                "raw bytes and padding do not match capacity",
            ));
        }
        if value_from_raw(entry.format, entry.raw)? != entry.value {
            return Err(Error::Malformed(
                "typed value disagrees with raw bytes or format",
            ));
        }
        data_len = add_size(align(data_len)?, capacity)?;
    }
    let values = align(add_size(keys, key_len)?)?;
    let total = add_size(values, data_len)?;
    let mut output = vec![0; total];
    output[..4].copy_from_slice(b"\0PSF");
    // All offsets and lengths are bounded by MAX_SIZE before narrowing to u32.
    put(&mut output, 4, sfo.version);
    put(&mut output, 8, keys as u32);
    put(&mut output, 12, values as u32);
    put(&mut output, 16, sfo.entries.len() as u32);
    key_len = 0;
    data_len = 0;
    for (i, entry) in sfo.entries.iter().enumerate() {
        let record = HEADER_SIZE + i * INDEX_SIZE;
        let key_offset =
            u16::try_from(key_len).map_err(|_| Error::LimitExceeded("key offset exceeds u16"))?;
        output[record..record + 2].copy_from_slice(&key_offset.to_le_bytes());
        output[record + 2..record + 4].copy_from_slice(&entry.format.to_le_bytes());
        put(&mut output, record + 4, entry.raw.len() as u32);
        put(&mut output, record + 8, entry.max_len);
        data_len = align(data_len)?;
        put(&mut output, record + 12, data_len as u32);
        output[keys + key_len..keys + key_len + entry.key.len()].copy_from_slice(entry.key);
        key_len += entry.key.len() + 1;
        let start = values + data_len;
        let end = start + entry.raw.len();
        output[start..end].copy_from_slice(entry.raw);
        output[end..end + entry.padding.len()].copy_from_slice(entry.padding);
        data_len += entry.max_len as usize;
    }
    Ok(output)
}

fn put(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
