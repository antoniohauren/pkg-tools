#![cfg(unix)]

use pkg_ops::{extract, extract_selected, was_cancelled};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

const PS3: &[u8] = include_bytes!("../../../tests/fixtures/ps3-list-explicit.pkg");
const PS3_IMPLIED: &[u8] = include_bytes!("../../../tests/fixtures/ps3-list-implied.pkg");
const PS4: &[u8] = include_bytes!("../../../tests/fixtures/ps4-selection.pkg");

struct Fixture(PathBuf);
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "pkg-ops-selection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("input.pkg"), bytes).unwrap();
        Self(root)
    }
    fn source(&self) -> PathBuf {
        self.0.join("input.pkg")
    }
    fn output(&self) -> PathBuf {
        self.0.join("output")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// None denotes a directory; Some contains the exact file contents.
fn tree(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(root: &Path, directory: &Path, result: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let value = if path.is_dir() {
                None
            } else {
                Some(fs::read(&path).unwrap())
            };
            result.insert(name, value);
            if path.is_dir() {
                walk(root, &path, result);
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

fn expected(paths: &[&str]) -> BTreeMap<String, Option<Vec<u8>>> {
    paths
        .iter()
        .map(|&path| {
            let contents = match path {
                "README.txt" => Some(b"readme".to_vec()),
                "data/one.bin" => Some(b"one".to_vec()),
                "data/nested/two.bin" => Some(b"two!".to_vec()),
                "data/nested/zero.bin" => Some(vec![]),
                "data/unused.bin" => Some(b"unused".to_vec()),
                "database/other.bin" => Some(b"other".to_vec()),
                "sce_sys/param.sfo" => Some(b"SFO".to_vec()),
                "data" | "data/nested" | "data/nested/empty" | "database" | "empty" | "sce_sys" => {
                    None
                }
                _ => panic!("unexpected test path: {path}"),
            };
            (path.to_owned(), contents)
        })
        .collect()
}

fn selection(bytes: &[u8], selected: &[&str], paths: &[&str]) {
    // Reverse order must resolve the same union, including repeated selections.
    for selected in [selected.to_vec(), selected.iter().rev().copied().collect()] {
        let fixture = Fixture::new(bytes);
        let mut updates = Vec::new();
        let result = extract_selected(
            &fixture.source(),
            &fixture.output(),
            &selected,
            &AtomicBool::new(false),
            |n, total| updates.push((n, total)),
        );
        if selected.is_empty() {
            assert!(result.is_err());
            assert!(!fixture.output().exists());
            assert!(updates.is_empty());
        } else {
            result.unwrap();
            let expected = expected(paths);
            assert_eq!(tree(&fixture.output()), expected);
            let total: u64 = expected
                .values()
                .filter_map(Option::as_ref)
                .map(|v| v.len() as u64)
                .sum();
            assert_eq!(updates.first(), Some(&(0, total)));
            assert_eq!(updates.last(), Some(&(total, total)));
            assert!(
                updates
                    .windows(2)
                    .all(|p| p[0].0 < p[1].0 && p[1].1 == total)
            );
            // Exclusive output creation also makes any repeated entry processing fail.
            assert!(!fixture.output().join("database/other.bin").exists());
        }
        assert_eq!(fs::read(fixture.source()).unwrap(), bytes);
    }
}

macro_rules! cases {
    ($($ps3:ident, $ps4:ident: $selected:expr => $paths:expr;)*) => {$(
        #[test]
        fn $ps3() {
            for bytes in [PS3, PS3_IMPLIED] { selection(bytes, $selected, $paths); }
        }
        #[test]
        fn $ps4() { selection(PS4, $selected, $paths); }
    )*};
}

const NESTED: &[&str] = &[
    "data",
    "data/nested",
    "data/nested/empty",
    "data/nested/two.bin",
    "data/nested/zero.bin",
];
const SUBTREE: &[&str] = &[
    "data",
    "data/nested",
    "data/nested/empty",
    "data/nested/two.bin",
    "data/nested/zero.bin",
    "data/one.bin",
    "data/unused.bin",
];
cases! {
    ps3_selection_none, ps4_selection_none: &[] => &[];
    ps3_selection_clear, ps4_selection_clear: &[] => &[];
    ps3_selection_file, ps4_selection_file: &["data/nested/two.bin"] => &["data", "data/nested", "data/nested/two.bin"];
    ps3_selection_files, ps4_selection_files: &["README.txt", "data/one.bin"] => &["README.txt", "data", "data/one.bin"];
    ps3_selection_folder, ps4_selection_folder: &["data/nested"] => NESTED;
    ps3_selection_subtree, ps4_selection_subtree: &["data"] => SUBTREE;
    ps3_selection_overlap, ps4_selection_overlap: &["data", "data/nested", "data/nested/two.bin"] => SUBTREE;
    ps3_selection_duplicate, ps4_selection_duplicate: &["data/one.bin", "data/one.bin"] => &["data", "data/one.bin"];
    ps3_selection_empty_folder, ps4_selection_empty_folder: &["empty"] => &["empty"];
    ps3_selection_nested_empty_folder, ps4_selection_nested_empty_folder: &["data/nested/empty"] => &["data", "data/nested", "data/nested/empty"];
    ps3_selection_zero_byte_file, ps4_selection_zero_byte_file: &["data/nested/zero.bin"] => &["data", "data/nested", "data/nested/zero.bin"];
    ps3_selection_mixed, ps4_selection_mixed: &["README.txt", "data/nested", "empty"] => &["README.txt", "data", "data/nested", "data/nested/empty", "data/nested/two.bin", "data/nested/zero.bin", "empty"];
}

#[test]
fn full_extraction_still_includes_every_entry() {
    for bytes in [PS3, PS3_IMPLIED, PS4] {
        let fixture = Fixture::new(bytes);
        extract(
            &fixture.source(),
            &fixture.output(),
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        let mut paths = SUBTREE.to_vec();
        paths.extend(["README.txt", "database", "database/other.bin", "empty"]);
        if bytes == PS4 {
            paths.extend(["sce_sys", "sce_sys/param.sfo"]);
        }
        assert_eq!(tree(&fixture.output()), expected(&paths));
        assert_eq!(fs::read(fixture.source()).unwrap(), bytes);
    }
}

#[test]
fn selected_extraction_preserves_safety_and_cancellation() {
    for bytes in [PS3, PS3_IMPLIED, PS4] {
        let fixture = Fixture::new(bytes);
        for selected in [
            &["missing"][..],
            &["data", "missing"],
            &["../README.txt"],
            &["/data"],
            &["DATA"],
            &["data/"],
            &["data/../README.txt"],
            &["data//one.bin"],
            &["data\\one.bin"],
            &[".pkg-tools-incomplete"],
            &["data/one.bin\0"],
        ] {
            assert!(
                extract_selected(
                    &fixture.source(),
                    &fixture.output(),
                    selected,
                    &AtomicBool::new(false),
                    |_, _| panic!("invalid selection started extraction")
                )
                .is_err()
            );
            assert!(!fixture.output().exists());
        }
        let cancelled = AtomicBool::new(true);
        let error = extract_selected(
            &fixture.source(),
            &fixture.output(),
            &["data"],
            &cancelled,
            |_, _| {},
        )
        .unwrap_err();
        assert!(was_cancelled(error.as_ref()));
        assert!(!fixture.output().exists());
        cancelled.store(false, Ordering::Relaxed);
        let error = extract_selected(
            &fixture.source(),
            &fixture.output(),
            &["data"],
            &cancelled,
            |n, _| {
                if n > 0 {
                    cancelled.store(true, Ordering::Relaxed);
                }
            },
        )
        .unwrap_err();
        assert!(was_cancelled(error.as_ref()));
        assert!(fixture.output().join(".pkg-tools-incomplete").exists());
        let before = tree(&fixture.output());
        cancelled.store(false, Ordering::Relaxed);
        assert!(
            extract_selected(
                &fixture.source(),
                &fixture.output(),
                &["data"],
                &cancelled,
                |_, _| {}
            )
            .is_err()
        );
        assert_eq!(tree(&fixture.output()), before);
        std::os::unix::fs::symlink(fixture.output(), fixture.0.join("link")).unwrap();
        assert!(
            extract_selected(
                &fixture.source(),
                &fixture.0.join("link/escape"),
                &["data"],
                &cancelled,
                |_, _| {}
            )
            .is_err()
        );
        assert!(!fixture.output().join("escape").exists());
        assert_eq!(fs::read(fixture.source()).unwrap(), bytes);
    }
}

#[test]
fn selected_extraction_refuses_existing_destinations() {
    for bytes in [PS3, PS3_IMPLIED, PS4] {
        let fixture = Fixture::new(bytes);
        extract_selected(
            &fixture.source(),
            &fixture.output(),
            &["README.txt"],
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        let before = tree(&fixture.output());
        assert!(!fixture.output().join(".pkg-tools-incomplete").exists());
        fs::write(fixture.0.join("existing-file"), b"keep me").unwrap();
        fs::create_dir(fixture.0.join("existing-empty-folder")).unwrap();
        std::os::unix::fs::symlink(fixture.output(), fixture.0.join("existing-link")).unwrap();
        for destination in [
            fixture.output(),
            fixture.0.join("existing-file"),
            fixture.0.join("existing-empty-folder"),
            fixture.0.join("existing-link"),
            fixture.source(),
        ] {
            assert!(
                extract_selected(
                    &fixture.source(),
                    &destination,
                    &["data"],
                    &AtomicBool::new(false),
                    |_, _| {},
                )
                .is_err(),
                "accepted existing destination: {}",
                destination.display()
            );
            assert_eq!(tree(&fixture.output()), before);
            assert_eq!(
                fs::read(fixture.0.join("existing-file")).unwrap(),
                b"keep me"
            );
            assert_eq!(
                fs::read_dir(fixture.0.join("existing-empty-folder"))
                    .unwrap()
                    .count(),
                0
            );
            assert_eq!(fs::read(fixture.source()).unwrap(), bytes);
        }
    }
}

#[test]
fn ps4_selection_includes_container_metadata() {
    selection(
        PS4,
        &["sce_sys/param.sfo", "sce_sys"],
        &["sce_sys", "sce_sys/param.sfo"],
    );
}

#[test]
fn ps4_selection_cancels_between_chunks() {
    let fixture = Fixture::new(include_bytes!("../../../tests/fixtures/ps4-nested.pkg"));
    let cancelled = AtomicBool::new(false);
    let mut updates = Vec::new();
    let error = extract_selected(
        &fixture.source(),
        &fixture.output(),
        &["eboot.bin"],
        &cancelled,
        |n, total| {
            updates.push((n, total));
            if n > 0 {
                cancelled.store(true, Ordering::Relaxed);
            }
        },
    )
    .unwrap_err();
    assert!(was_cancelled(error.as_ref()));
    assert_eq!(updates, [(0, 65537), (65536, 65537)]);
    assert_eq!(
        fs::metadata(fixture.output().join("eboot.bin"))
            .unwrap()
            .len(),
        65536
    );
    assert!(fixture.output().join(".pkg-tools-incomplete").exists());
    assert!(!fixture.output().join("sce_sys").exists());
}
