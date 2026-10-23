//! Shared package workflows for command-line and graphical frontends.

pub mod convert;
pub mod liberate;
mod listing;

pub use listing::{FileEntry, FileKind, list};

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
    extract_selection(source, destination, None, cancelled, progress)
}

/// Extract exact application paths and their subtrees to a new directory.
/// Includes required parents and deduplicates overlaps. Empty/unknown selections
/// fail without output; progress reports only selected files' decoded bytes.
pub fn extract_selected(
    source: &Path,
    destination: &Path,
    selected: &[&str],
    cancelled: &AtomicBool,
    progress: impl FnMut(u64, u64),
) -> Result<(), Box<dyn std::error::Error>> {
    if selected.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty extraction selection",
        )
        .into());
    }
    extract_selection(source, destination, Some(selected), cancelled, progress)
}

fn extract_selection(
    source: &Path,
    destination: &Path,
    selected: Option<&[&str]>,
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
    let is_cancelled = || cancelled.load(Ordering::Relaxed);
    if magic == *b"\x7fPKG" {
        let mut package = ps3_pkg::Package::open(reader)?;
        if let Some(selected) = selected {
            package.extract_selected_with_progress(
                destination,
                selected,
                is_cancelled,
                progress,
            )?;
        } else {
            package.extract_with_progress(destination, is_cancelled, progress)?;
        }
        return Ok(());
    }
    ps4_pkg::Package::open(reader)
        .and_then(|pkg| pkg.open_game())
        .and_then(|mut game| {
            if let Some(selected) = selected {
                game.extract_selected_with_progress(destination, selected, is_cancelled, progress)
            } else {
                game.extract_with_progress(destination, is_cancelled, progress)
            }
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
