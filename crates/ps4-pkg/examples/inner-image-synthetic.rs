//! Disposable non-executable image for independent reader checks, not a PKG build.
use ps4_pkg::inner_image::{Entry, InnerImage};
use std::{io, path::PathBuf};

fn main() -> io::Result<()> {
    let output = PathBuf::from(std::env::args_os().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected new .pfs or .pfsc output",
        )
    })?);
    let mut entries = vec![
        Entry {
            path: "A~".into(),
            size: Some(0),
        },
        Entry {
            path: "B_".into(),
            size: None,
        },
        Entry {
            path: "data".into(),
            size: None,
        },
        Entry {
            path: "data/boundary.bin".into(),
            size: Some(13 * 65536 + 1),
        },
        Entry {
            path: "empty-dir".into(),
            size: None,
        },
    ];
    entries.extend((0..9000).map(|i| Entry {
        path: format!("file{i:05}"),
        size: Some(0),
    }));
    InnerImage::new(&entries, 123)?.write_new(
        &output,
        |index, offset, bytes| {
            if index != 3 {
                return Err(io::Error::other("unexpected synthetic payload"));
            }
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = ((offset + i as u64) % 251) as u8;
            }
            Ok(())
        },
        || false,
    )
}
