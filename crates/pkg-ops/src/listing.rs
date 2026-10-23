use std::{
    fs::File,
    io::{self, BufReader, Read, Seek},
    path::Path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
}

/// One application entry, including explicit and inferred parent directories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    /// Portable, slash-separated path relative to the application root.
    pub path: String,
    pub kind: FileKind,
    /// Decoded file size in bytes; zero for directories.
    pub size: u64,
}

/// List a supported PS3/PS4 application's files without extracting payloads.
/// Opens the source read-only and decodes directory metadata in memory, using
/// the format readers' existing path validation and resource limits. PS4 includes
/// application metadata under `sce_sys`, not the outer container's file tree.
/// This does not authenticate every payload block or decode nested SELF/EDAT files.
pub fn list(source: &Path) -> Result<Vec<FileEntry>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(source)?);
    let mut magic = [0; 4];
    reader.read_exact(&mut magic)?;
    reader.rewind()?;
    match &magic {
        b"\x7fPKG" => Ok(ps3_pkg::Package::open(reader)?
            .entries()
            .iter()
            .map(|entry| FileEntry {
                path: entry.path().to_owned(),
                kind: match entry.kind() {
                    ps3_pkg::FileKind::File => FileKind::File,
                    ps3_pkg::FileKind::Directory => FileKind::Directory,
                },
                size: entry.size(),
            })
            .collect()),
        b"\x7fCNT" => Ok(ps4_pkg::Package::open(reader)?
            .open_game()?
            .entries()
            .iter()
            .map(|entry| FileEntry {
                path: entry.path().to_owned(),
                kind: match entry.kind() {
                    ps4_pkg::FileKind::File => FileKind::File,
                    ps4_pkg::FileKind::Directory => FileKind::Directory,
                },
                size: entry.size(),
            })
            .collect()),
        _ => Err(io::Error::new(io::ErrorKind::Unsupported, "not a PS3 or PS4 package").into()),
    }
}
