use std::{
    fmt::Write,
    fs::File,
    io::{BufReader, Read, Seek},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Details {
    pub can_convert: bool,
    pub title: String,
    pub size: u64,
    pub content_id: String,
    pub status: String,
    pub metadata: String,
    pub title_id: String,
    pub version: String,
    pub kind: String,
    pub category: String,
    pub icon: Option<Vec<u8>>,
}

fn category(value: &[u8]) -> String {
    match value {
        b"gd" | b"HG" | b"DG" => "Game".into(),
        b"gp" => "Patch".into(),
        b"GD" => "Game data / patch".into(),
        b"ac" => "Add-on".into(),
        other => format!("Other ({})", text(other)),
    }
}

// Limit decoded image memory as well as the container entry's encoded size.
pub fn valid_icon(bytes: &[u8]) -> bool {
    bytes.len() >= 24
        && &bytes[..8] == b"\x89PNG\r\n\x1a\n"
        && bytes[8..12] == 13u32.to_be_bytes()
        && &bytes[12..16] == b"IHDR"
        && (1..=2048).contains(&u32::from_be_bytes(bytes[16..20].try_into().unwrap()))
        && (1..=2048).contains(&u32::from_be_bytes(bytes[20..24].try_into().unwrap()))
}

fn text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(value) => value.to_owned(),
        Err(_) => format!("{bytes:02x?} (non-UTF-8)"),
    }
}

pub fn inspect(path: &Path) -> Result<Details, String> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| e.to_string())?);
    let mut magic = [0; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|e| ps4_pkg::Error::from(e).to_string())?;
    reader.rewind().map_err(|e| e.to_string())?;
    if magic == *b"\x7fPKG" {
        return inspect_ps3(reader, path);
    }
    let mut pkg = ps4_pkg::Package::open(reader).map_err(|e| e.to_string())?;
    let h = pkg.header();
    let mut details = Details {
        can_convert: true,
        title: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        size: h.package_size,
        content_id: text(h.content_id.split(|b| *b == 0).next().unwrap_or_default()),
        status: String::new(),
        title_id: "Unknown".into(),
        version: "Unknown".into(),
        kind: "Unknown".into(),
        category: "gd".into(),
        icon: None,
        metadata: format!(
            "Format: PS4 PKG\nFlags: {:#x}\nDRM type: {:#x}\nContent type: {:#x}\nContent flags: {:#x}\nContainer entries: {}\nEntry table offset: {}\nBody offset: {}\nBody size: {}\nPFS flags: {:#x}\nPFS offset: {}\nPFS size: {}\n",
            h.flags,
            h.drm_type,
            h.content_type,
            h.content_flags,
            h.entry_count,
            h.entry_table_offset,
            h.body_offset,
            h.body_size,
            h.pfs_flags,
            h.pfs_offset,
            h.pfs_size
        ),
    };
    match pkg.read_param_sfo() {
        Ok(Some(bytes)) => {
            apply_sfo(&mut details, &bytes)?;
        }
        Ok(None) => details.status = "PARAM.SFO missing".into(),
        Err(ps4_pkg::Error::DecryptionUnavailable { .. }) => {
            details.status = "PARAM.SFO encrypted · decryption unavailable".into();
        }
        Err(e) => return Err(e.to_string()),
    }
    details.metadata.insert_str(
        0,
        &format!(
            "Source: {}\nPackage size: {} bytes\nContent ID: {}\n",
            path.display(),
            details.size,
            details.content_id
        ),
    );
    match pkg.read_icon0() {
        Ok(Some(bytes)) if valid_icon(&bytes) => details.icon = Some(bytes),
        Ok(Some(_)) => details
            .metadata
            .push_str("\nArtwork: invalid PNG or dimensions exceed 2048 × 2048\n"),
        Ok(None) => details.metadata.push_str("\nArtwork: not available\n"),
        Err(e) => {
            writeln!(details.metadata, "\nArtwork: {e}").unwrap();
        }
    }
    details
        .metadata
        .push_str("\nCONTAINER ENTRIES (not application files)\n");
    for entry in pkg.entries() {
        writeln!(details.metadata, "ID {:#x} · offset {} · size {} · name offset {} · flags {:#x}/{:#x} · encrypted {} · key {}",
            entry.id, entry.offset, entry.size, entry.name_offset, entry.flags1, entry.flags2, entry.encrypted(), entry.key_index()).unwrap();
    }
    Ok(details)
}

fn apply_sfo(details: &mut Details, bytes: &[u8]) -> Result<(), String> {
    let sfo = psf::parse(bytes).map_err(|e| e.to_string())?;
    details.status = format!("PARAM.SFO · version {:#x}", sfo.version);
    details.metadata.push_str("\nPARAM.SFO\n");
    for entry in sfo.entries {
        if let psf::Value::Text(bytes) = entry.value {
            match entry.key {
                b"TITLE_ID" => details.title_id = text(bytes),
                b"APP_VER" => details.version = text(bytes),
                b"CATEGORY" => {
                    details.kind = category(bytes);
                    details.category = text(bytes);
                }
                _ => {}
            }
        }
        let value = match entry.value {
            psf::Value::Text(bytes) => text(bytes),
            psf::Value::Integer(n) => n.to_string(),
            psf::Value::Binary(bytes) | psf::Value::Unknown { bytes, .. } => {
                // shortcut: binary previews stop at 64 bytes; use CLI JSON for complete raw values.
                format!(
                    "{:02x?} ({} bytes, format {:#x})",
                    &bytes[..bytes.len().min(64)],
                    bytes.len(),
                    entry.format
                )
            }
        };
        if entry.key == b"TITLE" {
            details.title = value.clone();
        }
        writeln!(details.metadata, "{}: {}", text(entry.key), value).unwrap();
    }
    Ok(())
}

fn inspect_ps3(reader: BufReader<File>, path: &Path) -> Result<Details, String> {
    let mut pkg = ps3_pkg::Package::open(reader).map_err(|e| e.to_string())?;
    let h = pkg.header();
    let mut details = Details {
        can_convert: false,
        title: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        size: h.package_size,
        content_id: text(h.content_id.split(|b| *b == 0).next().unwrap_or_default()),
        status: "PARAM.SFO missing".into(),
        title_id: "Unknown".into(),
        version: "Unknown".into(),
        kind: "Unknown".into(),
        category: String::new(),
        icon: None,
        metadata: format!(
            "Source: {}\nFormat: PS3 PKG\nPackage size: {} bytes\nRelease type: {:#x}\nPlatform: {}\nPackage entries: {}\nMetadata offset: {}\nMetadata count: {}\nMetadata size: {}\nData offset: {}\nData size: {}\nSignatures: unverified\n",
            path.display(),
            h.package_size,
            h.release_type,
            h.platform,
            h.entry_count,
            h.metadata_offset,
            h.metadata_count,
            h.metadata_size,
            h.data_offset,
            h.data_size
        ),
    };
    writeln!(details.metadata, "Content ID: {}", details.content_id).unwrap();
    if let Some(bytes) = pkg.read_param_sfo().map_err(|e| e.to_string())? {
        apply_sfo(&mut details, &bytes)?;
    }
    match pkg.read_icon0() {
        Ok(Some(bytes)) if valid_icon(&bytes) => details.icon = Some(bytes),
        Ok(Some(_)) => details
            .metadata
            .push_str("\nArtwork: invalid PNG or dimensions exceed 2048 × 2048\n"),
        Ok(None) => details.metadata.push_str("\nArtwork: not available\n"),
        Err(e) => {
            writeln!(details.metadata, "\nArtwork: {e}").unwrap();
        }
    }
    details.metadata.push_str("\nPACKAGE METADATA\n");
    for item in pkg.metadata() {
        writeln!(
            details.metadata,
            "ID {:#x} · {} bytes · {:02x?}",
            item.id,
            item.data.len(),
            &item.data[..item.data.len().min(64)]
        )
        .unwrap();
    }
    details.metadata.push_str("\nAPPLICATION ENTRIES\n");
    for entry in pkg.entries() {
        writeln!(
            details.metadata,
            "{} · {:?} · offset {} · size {} · flags {:#x}",
            entry.path(),
            entry.kind(),
            entry.offset(),
            entry.size(),
            entry.flags()
        )
        .unwrap();
    }
    Ok(details)
}

pub fn destination(source: &Path, parent: &Path, suffix: &str) -> PathBuf {
    let name = (if source.is_dir() {
        source.file_name()
    } else {
        source.file_stem()
    })
    .unwrap_or_default()
    .to_string_lossy();
    // RPCS3 cellGameBootCheck requires HDD-game directory names below 32 bytes.
    let mut end = name.len().min(31 - suffix.len());
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    parent.join(format!("{}{suffix}", &name[..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_categories_and_artwork_limits() {
        assert_eq!(category(b"gd"), "Game");
        assert_eq!(category(b"gp"), "Patch");
        assert_eq!(category(b"ac"), "Add-on");
        assert_eq!(category(b"HG"), "Game");
        assert_eq!(category(b"GD"), "Game data / patch");
        assert_eq!(category(b"xx"), "Other (xx)");
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&512u32.to_be_bytes());
        png.extend_from_slice(&512u32.to_be_bytes());
        assert!(valid_icon(&png));
        png[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(!valid_icon(&png));
        assert!(!valid_icon(b"not a PNG"));
    }

    #[test]
    fn ps3_metadata_loads_and_disables_conversion() {
        let hex: String = include_str!("../../../tests/fixtures/ps3-debug.hex")
            .split_whitespace()
            .collect();
        let data: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let path = std::env::temp_dir().join(format!("pkg-gtk-ps3-{}.pkg", std::process::id()));
        std::fs::write(&path, data).unwrap();
        let details = inspect(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(details.title, "Synthetic");
        assert!(details.metadata.contains("Format: PS3 PKG"));
        assert!(details.metadata.contains("PARAM.SFO"));
        assert!(!details.can_convert);
    }

    #[test]
    fn destination_stays_inside_selected_parent() {
        assert_eq!(
            destination(
                Path::new("/source/game.pkg"),
                Path::new("/output"),
                "-extracted"
            ),
            Path::new("/output/game-extracted")
        );
        assert_eq!(
            destination(
                Path::new("/source/..pkg"),
                Path::new("/output"),
                "-extracted"
            ),
            Path::new("/output/.-extracted")
        );
    }

    #[test]
    fn destination_fits_rpcs3_hdd_game_directory_buffer() {
        for stem in [
            "x".repeat(21),
            "x".repeat(22),
            "x".repeat(100),
            "遊".repeat(40),
        ] {
            let source = PathBuf::from(format!("{stem}.pkg"));
            for suffix in ["-extracted", "-liberated"] {
                let path = destination(&source, Path::new("/output"), suffix);
                let name = path.file_name().unwrap().to_str().unwrap();
                assert!(name.len() < 32, "RPCS3 cellGameBootCheck rejects {name}");
                assert!(name.ends_with(suffix));
                assert_eq!(path.parent(), Some(Path::new("/output")));
            }
        }
    }

    #[test]
    fn invalid_text_is_explicit_and_invalid_packages_fail() {
        assert_eq!(text(b"Title"), "Title");
        assert!(text(&[0xff]).contains("non-UTF-8"));
        assert!(
            inspect(Path::new("/dev/null"))
                .unwrap_err()
                .contains("truncated")
        );
    }
}
