//! Shared package workflows for command-line and graphical frontends.

pub mod convert;
pub mod liberate;

use std::{
    fs::File,
    io::{BufReader, Read, Seek},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

/// Detects PS3/PS4 input and extracts to a new directory without overwriting.
/// Cancellation may leave an incomplete tree, identified by the returned error.
pub fn extract(
    source: &Path,
    destination: &Path,
    cancelled: &AtomicBool,
    progress: impl FnMut(u64, u64),
) -> Result<(), Box<dyn std::error::Error>> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(ps4_pkg::Error::Cancelled.into());
    }
    let mut reader = BufReader::new(File::open(source)?);
    let mut magic = [0; 4];
    reader.read_exact(&mut magic)?;
    reader.rewind()?;
    if magic == *b"\x7fPKG" {
        ps3_pkg::Package::open(reader)?.extract_with_progress(
            destination,
            || cancelled.load(Ordering::Relaxed),
            progress,
        )?;
        return Ok(());
    }
    ps4_pkg::Package::open(reader)
        .and_then(|pkg| pkg.open_game())
        .and_then(|mut game| {
            game.extract_with_progress(destination, || cancelled.load(Ordering::Relaxed), progress)
        })?;
    Ok(())
}

/// Recognizes cancellation, including errors wrapping an incomplete output tree.
pub fn was_cancelled(error: &(dyn std::error::Error + 'static)) -> bool {
    matches!(
        error.downcast_ref::<ps4_pkg::Error>(),
        Some(ps4_pkg::Error::Cancelled)
    ) || matches!(
        error.downcast_ref::<ps3_pkg::Error>(),
        Some(ps3_pkg::Error::Cancelled)
    ) || error.source().is_some_and(was_cancelled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_includes_incomplete_output_errors() {
        assert!(was_cancelled(&ps4_pkg::Error::Cancelled));
        assert!(!was_cancelled(&ps4_pkg::Error::Malformed("bad data")));
        assert!(was_cancelled(&ps4_pkg::Error::IncompleteExtraction {
            path: "/output".into(),
            source: Box::new(ps4_pkg::Error::Cancelled),
        }));
        assert!(was_cancelled(&ps3_pkg::Error::IncompleteExtraction {
            path: "/output".into(),
            source: Box::new(ps3_pkg::Error::Cancelled),
        }));
        let error = extract(
            Path::new("missing.pkg"),
            Path::new("unused-output"),
            &AtomicBool::new(true),
            |_, _| {},
        )
        .unwrap_err();
        assert!(was_cancelled(error.as_ref()));
    }
}
