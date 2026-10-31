//! Original, public synthetic image/key. Not an executable or installable PKG.
use ps4_pkg::{
    inner_image::{Entry, InnerImage},
    outer_image::OuterImage,
};
use std::{io, path::Path};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 && args.len() != 3 {
        return Err(io::Error::other("expected output.pfs [double]"));
    }
    let size = match args.get(2).map(String::as_str) {
        None => 13 * 65536 + 1,
        Some("double") => 1835 * 65536 + 1,
        _ => return Err(io::Error::other("expected double or no option")),
    };
    let inner = InnerImage::new(
        &[Entry {
            path: "pattern.bin".into(),
            size: Some(size),
        }],
        123,
    )?;
    OuterImage::new(&inner, 123)?.write_new(
        Path::new(&args[1]),
        &std::array::from_fn(|i| i as u8),
        |_, offset, b| {
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = ((offset + i as u64) % 251) as u8;
            }
            Ok(())
        },
        || false,
    )
}
