use crate::{
    Error,
    input::{ReadAt, le32, le64},
    range,
};
use flate2::{Decompress, FlushDecompress, Status};

pub(crate) struct Pfsc<T> {
    source: T,
    size: u64,
    block: u64,
    table: u64,
    cached: Option<u64>,
    decoded: Vec<u8>,
    stored: Vec<u8>,
}

impl<T: ReadAt> Pfsc<T> {
    pub fn open(mut source: T) -> Result<Self, Error> {
        let mut h = [0; 48];
        source.read_at(0, &mut h)?;
        if &h[..4] != b"PFSC" || le32(&h, 4) != 0 {
            return Err(Error::Malformed("PFSC header"));
        }
        let block = le64(&h, 16);
        if block != u64::from(le32(&h, 12))
            || !block.is_power_of_two()
            || !(4096..=65536).contains(&block)
        {
            return Err(Error::Unsupported("PFSC block size"));
        }
        let table = le64(&h, 24);
        let start = le64(&h, 32);
        let size = le64(&h, 40);
        if size == 0 || !size.is_multiple_of(block) {
            return Err(Error::Malformed("PFSC logical size"));
        }
        let count = size / block;
        let table_size = count
            .checked_add(1)
            .and_then(|n| n.checked_mul(8))
            .ok_or(Error::Malformed("PFSC table overflow"))?;
        range(table, table_size, source.len())?;
        if table < 48 || start < table + table_size || start > source.len() {
            return Err(Error::Malformed("PFSC table/data overlap"));
        }
        // Validate every offset with a fixed buffer; the index never scales RAM with payload.
        let mut buf = [0; 8192];
        let mut previous = None;
        let mut index = 0;
        while index <= count {
            let n = (count + 1 - index).min(1024) as usize;
            source.read_at(table + index * 8, &mut buf[..n * 8])?;
            for j in 0..n {
                let offset = le64(&buf, j * 8);
                if offset < start || offset > source.len() {
                    return Err(Error::Malformed("PFSC block offset"));
                }
                if let Some(p) = previous
                    && (offset <= p || offset - p > block)
                {
                    return Err(Error::Unsupported("PFSC empty/oversized block"));
                }
                previous = Some(offset);
            }
            index += n as u64;
        }
        Ok(Self {
            source,
            size,
            block,
            table,
            cached: None,
            decoded: vec![0; block as usize],
            stored: vec![0; block as usize],
        })
    }
}

impl<T: ReadAt> ReadAt for Pfsc<T> {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&mut self, mut offset: u64, mut data: &mut [u8]) -> Result<(), Error> {
        range(offset, data.len() as u64, self.size)?;
        while !data.is_empty() {
            let index = offset / self.block;
            let within = (offset % self.block) as usize;
            let n = data.len().min(self.block as usize - within);
            if self.cached != Some(index) {
                self.cached = None;
                let mut pair = [0; 16];
                self.source.read_at(self.table + index * 8, &mut pair)?;
                let start = le64(&pair, 0);
                let end = le64(&pair, 8);
                let len = end
                    .checked_sub(start)
                    .filter(|v| *v > 0 && *v <= self.block)
                    .ok_or(Error::Malformed("PFSC block range changed"))?
                    as usize;
                self.source.read_at(start, &mut self.stored[..len])?;
                if len == self.block as usize {
                    self.decoded.copy_from_slice(&self.stored);
                } else {
                    let mut decoder = Decompress::new(true);
                    let status = decoder
                        .decompress(
                            &self.stored[..len],
                            &mut self.decoded,
                            FlushDecompress::Finish,
                        )
                        .map_err(|_| Error::Malformed("PFSC zlib data/checksum"))?;
                    if status != Status::StreamEnd
                        || decoder.total_in() != len as u64
                        || decoder.total_out() != self.block
                    {
                        return Err(Error::Malformed("PFSC decompressed length/trailing data"));
                    }
                }
                self.cached = Some(index);
            }
            data[..n].copy_from_slice(&self.decoded[within..within + n]);
            data = &mut data[n..];
            offset += n as u64;
        }
        Ok(())
    }
}
