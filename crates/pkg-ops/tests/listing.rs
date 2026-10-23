use pkg_ops::{FileEntry, FileKind, list};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let root = std::env::temp_dir().join(format!("pkg-ops-list-{name}-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("input.pkg"), bytes).unwrap();
        Self(root)
    }

    fn list(&self) -> Vec<FileEntry> {
        let source = self.0.join("input.pkg");
        let original = fs::read(&source).unwrap();
        let entries = list(&source).unwrap();
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read_dir(&self.0).unwrap().count(), 1);
        entries
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn entry(path: &str, kind: FileKind, size: u64) -> FileEntry {
    FileEntry {
        path: path.into(),
        kind,
        size,
    }
}

#[test]
fn ps3_listing_explicit_and_implied_parents() {
    use FileKind::{Directory, File};
    let expected = vec![
        entry("data", Directory, 0),
        entry("data/nested", Directory, 0),
        entry("data/nested/empty", Directory, 0),
        entry("data/nested/two.bin", File, 4),
        entry("data/nested/zero.bin", File, 0),
        entry("data/one.bin", File, 3),
        entry("data/unused.bin", File, 6),
        entry("database", Directory, 0),
        entry("database/other.bin", File, 5),
        entry("empty", Directory, 0),
        entry("README.txt", File, 6),
    ];
    for (name, bytes) in [
        (
            "ps3-explicit",
            include_bytes!("../../../tests/fixtures/ps3-list-explicit.pkg").as_slice(),
        ),
        (
            "ps3-implied",
            include_bytes!("../../../tests/fixtures/ps3-list-implied.pkg").as_slice(),
        ),
    ] {
        assert_eq!(Fixture::new(name, bytes).list(), expected);
    }
}

#[test]
fn ps4_listing_decodes_nested_pfs_and_includes_application_metadata() {
    use FileKind::{Directory, File};
    let fixture = Fixture::new(
        "ps4",
        include_bytes!("../../../tests/fixtures/ps4-nested.pkg"),
    );
    assert_eq!(
        fixture.list(),
        vec![
            entry("eboot.bin", File, 65537),
            entry("empty", File, 0),
            entry("empty-dir", Directory, 0),
            entry("sce_sys", Directory, 0),
            entry("sce_sys/param.sfo", File, 3),
        ]
    );
}

#[test]
fn listing_errors_preserve_format_validation_and_limits() {
    let ps3 = include_bytes!("../../../tests/fixtures/ps3-list-explicit.pkg");
    let ps4 = include_bytes!("../../../tests/fixtures/ps4-nested.pkg");
    let mut unsupported_ps3 = ps3.to_vec();
    unsupported_ps3[6..8].copy_from_slice(&2u16.to_be_bytes());
    let mut limited_ps3 = ps3.to_vec();
    limited_ps3[20..24].copy_from_slice(&1_000_001u32.to_be_bytes());
    // Keep the declared table range valid so the entry-count limit is reached.
    limited_ps3.resize(0x100 + 1_000_001 * 32, 0);
    let size = limited_ps3.len() as u64;
    limited_ps3[24..32].copy_from_slice(&size.to_be_bytes());
    let offset = u64::from_be_bytes(limited_ps3[32..40].try_into().unwrap());
    limited_ps3[40..48].copy_from_slice(&(size - offset).to_be_bytes());
    let mut unsupported_ps4 = ps4.to_vec();
    unsupported_ps4[0x74..0x78].copy_from_slice(&0x1eu32.to_be_bytes());
    let mut corrupt_ps4 = ps4.to_vec();
    corrupt_ps4[0x2400] ^= 1;
    let mut limited_ps4 = ps4.to_vec();
    limited_ps4[0x10..0x14].copy_from_slice(&65_537u32.to_be_bytes());
    limited_ps4.resize(0x1100 + 65_537 * 32, 0);
    let size = limited_ps4.len() as u64;
    limited_ps4[0x430..0x438].copy_from_slice(&size.to_be_bytes());
    for (name, bytes, message) in [
        (
            "unknown",
            b"not a package".as_slice(),
            "not a PS3 or PS4 package",
        ),
        (
            "ps3-platform",
            &unsupported_ps3,
            "unsupported PS3 package: platform",
        ),
        (
            "ps3-limit",
            &limited_ps3,
            "PS3 package limit exceeded: entry count",
        ),
        ("ps4-type", &unsupported_ps4, "GD base/full update"),
        ("ps4-keys", &corrupt_ps4, "key"),
        (
            "ps4-limit",
            &limited_ps4,
            "more than 65536 container entries",
        ),
        ("ps3-truncated", &ps3[..100], "truncated"),
        ("ps4-truncated", &ps4[..100], "truncated"),
    ] {
        let fixture = Fixture::new(name, bytes);
        let error = list(&fixture.0.join("input.pkg")).unwrap_err();
        assert!(error.to_string().contains(message), "{name}: {error}");
        assert_eq!(fs::read(fixture.0.join("input.pkg")).unwrap(), bytes);
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
    }
}
