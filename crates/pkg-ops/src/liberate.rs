//! PS3 liberation input handling and package/folder dispatch.

use std::{
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub fn read_rap(path: &Path) -> Result<ps3_pkg::Rap, Box<dyn std::error::Error>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err("RAP must be a regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(17).read_to_end(&mut bytes)?;
    Ok(ps3_pkg::Rap::from_bytes(&bytes)?)
}

pub fn liberation_content_id(source: &Path) -> Result<String, String> {
    let bytes = if source.is_dir() {
        let mut bytes = Vec::new();
        File::open(source.join("PARAM.SFO"))
            .map_err(|e| e.to_string())?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("PARAM.SFO exceeds 16 MiB".into());
        }
        let sfo = psf::parse(&bytes).map_err(|e| e.to_string())?;
        let content_id = sfo.entries.iter().find_map(|e| match (e.key, &e.value) {
            (b"CONTENT_ID", psf::Value::Text(value)) => Some(value.to_vec()),
            _ => None,
        });
        match content_id {
            Some(id) => id,
            None => ps3_pkg::self_content_id(
                File::open(source.join("USRDIR/EBOOT.BIN")).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
            .to_vec(),
        }
    } else {
        let package = ps3_pkg::Package::open(BufReader::new(
            File::open(source).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
        package.header().content_id.to_vec()
    };
    let id = bytes.split(|b| *b == 0).next().unwrap_or_default();
    if id.is_empty()
        || id.len() > 48
        || !id
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(b))
    {
        return Err("Invalid PS3 content ID".into());
    }
    Ok(String::from_utf8(id.to_vec()).unwrap())
}

pub fn find_rap(source: &Path, content_id: &str) -> Result<Option<PathBuf>, String> {
    let parent = source
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut roots = vec![parent.to_path_buf()];
    if source.is_dir() {
        roots.insert(0, source.to_path_buf());
    }
    let mut found = Vec::new();
    for root in roots {
        for directory in [root.clone(), root.join("exdata")] {
            let entries = match std::fs::read_dir(directory) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.to_string()),
            };
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                if entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&format!("{content_id}.rap"))
                {
                    found.push(entry.path());
                }
            }
        }
    }
    if found.len() > 1 {
        return Err("Multiple matching RAP files found. Link the intended RAP manually.".into());
    }
    if let Some(path) = found.first() {
        read_rap(path).map_err(|e| e.to_string())?;
    }
    Ok(found.pop())
}

/// Liberates a PS3 package or extracted folder into a new package or directory.
/// Sources remain untouched; interrupted directory output remains marked incomplete.
pub fn liberate(
    source: &Path,
    rap: &Path,
    output: &Path,
    directory: bool,
    cancelled: &AtomicBool,
    progress: impl FnMut(u64, u64),
) -> Result<(), Box<dyn std::error::Error>> {
    let rap = read_rap(rap)?;
    if source.is_dir() {
        let id = liberation_content_id(source)?;
        let mut cid = [0; 48];
        cid[..id.len()].copy_from_slice(id.as_bytes());
        let liberate = if directory {
            ps3_pkg::liberate_folder_to_directory_with_progress
        } else {
            ps3_pkg::liberate_folder_with_progress
        };
        liberate(
            source,
            cid,
            &rap,
            output,
            || cancelled.load(Ordering::Relaxed),
            progress,
        )?;
        return Ok(());
    }
    let mut package = ps3_pkg::Package::open(BufReader::new(File::open(source)?))?;
    if directory {
        package.liberate_to_directory_with_progress(
            &rap,
            output,
            || cancelled.load(Ordering::Relaxed),
            progress,
        )?;
    } else {
        package.liberate_with_progress(
            &rap,
            output,
            || cancelled.load(Ordering::Relaxed),
            progress,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rap_discovery_matches_content_id_and_rejects_ambiguity() {
        let root = std::env::temp_dir().join(format!("pkg-rap-discovery-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("unrelated-game-name.pkg");
        let id = "UP0001-TEST00001_00-0000000000000000";
        assert_eq!(find_rap(&source, id).unwrap(), None);
        std::fs::write(root.join("unrelated-game-name.rap"), [0; 16]).unwrap();
        assert_eq!(find_rap(&source, id).unwrap(), None);
        let rap = root.join(format!("{id}.RAP"));
        std::fs::write(&rap, [0; 15]).unwrap();
        assert!(find_rap(&source, id).is_err());
        std::fs::write(&rap, [0; 16]).unwrap();
        assert_eq!(find_rap(&source, id).unwrap(), Some(rap.clone()));
        std::fs::create_dir(root.join("exdata")).unwrap();
        let other = root.join("exdata").join(format!("{id}.rap"));
        std::fs::write(&other, [0; 16]).unwrap();
        assert!(find_rap(&source, id).is_err());
        std::fs::remove_file(rap).unwrap();
        assert_eq!(find_rap(&source, id).unwrap(), Some(other.clone()));
        let folder = root.join("extracted");
        std::fs::create_dir(&folder).unwrap();
        assert_eq!(find_rap(&folder, id).unwrap(), Some(other));
        assert!(liberation_content_id(&folder).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
