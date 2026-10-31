#![cfg(unix)]

use ps4_pkg::rebuild::{DEFAULT_PASSCODE, rebuild_new};
use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "pkg-tools-rebuild-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn has_scratch(&self) -> bool {
        fs::read_dir(&self.0).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".pkg-tools-image-")
        })
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        // Only this test's newly created files; never recurse into input trees.
        for entry in fs::read_dir(&self.0).unwrap() {
            let _ = fs::remove_file(entry.unwrap().path());
        }
        let _ = fs::remove_dir(&self.0);
    }
}

#[test]
fn output_and_source_aliases_never_replace_existing_bytes() {
    let temp = Scratch::new();
    let source = temp.path("source.pkg");
    let output = temp.path("output.pkg");
    fs::write(&source, b"source sentinel").unwrap();
    assert!(rebuild_new(&source, &source, &DEFAULT_PASSCODE, || false).is_err());
    fs::hard_link(&source, &output).unwrap();
    assert_eq!(
        rebuild_new(&source, &output, &DEFAULT_PASSCODE, || false)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&source).unwrap(), b"source sentinel");
    assert_eq!(fs::read(&output).unwrap(), b"source sentinel");
    fs::remove_file(&output).unwrap();
    symlink(&source, &output).unwrap();
    assert!(rebuild_new(&source, &output, &DEFAULT_PASSCODE, || false).is_err());
    assert!(!temp.has_scratch());
}

#[test]
fn symlink_sources_and_non_package_outputs_fail_without_scratch() {
    let temp = Scratch::new();
    let source = temp.path("source.pkg");
    let alias = temp.path("alias.pkg");
    fs::write(&source, b"source sentinel").unwrap();
    symlink(&source, &alias).unwrap();
    assert!(
        rebuild_new(&alias, &temp.path("output.pkg"), &DEFAULT_PASSCODE, || {
            false
        })
        .is_err()
    );
    assert!(
        rebuild_new(&source, &temp.path("output.pfs"), &DEFAULT_PASSCODE, || {
            false
        })
        .is_err()
    );
    assert!(!temp.has_scratch());
}

#[test]
#[ignore = "requires known-zero-passcode synthetic fixture from check-native-rebuild.py prepare"]
fn synthetic_native_rebuild_and_failure_cleanup() {
    let original = std::env::var_os("PKG_TOOLS_REBUILD_REFERENCE")
        .expect("set PKG_TOOLS_REBUILD_REFERENCE to synthetic fixture, never a private game");
    let temp = Scratch::new();
    let source = temp.path("source.pkg");
    let output = temp.path("native.pkg");
    fs::copy(&original, &source).unwrap();
    let original_bytes = fs::read(&source).unwrap();
    rebuild_new(&source, &output, &DEFAULT_PASSCODE, || false).unwrap();
    assert_ne!(
        fs::read(&output).unwrap(),
        original_bytes,
        "must rebuild, not copy source"
    );
    assert_eq!(fs::read(&source).unwrap(), original_bytes);
    assert!(!temp.has_scratch());

    let failed = temp.path("failed.pkg");
    assert!(rebuild_new(&source, &failed, &[b'1'; 32], || false).is_err());
    assert!(!failed.exists());
    assert!(!temp.has_scratch());

    let error =
        rebuild_new(&source, &failed, &DEFAULT_PASSCODE, || temp.has_scratch()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    assert!(!failed.exists());
    assert!(!temp.has_scratch());
    assert_eq!(fs::read(&source).unwrap(), original_bytes);

    let mut mutated = false;
    assert!(
        rebuild_new(&source, &failed, &DEFAULT_PASSCODE, || {
            if !mutated && temp.has_scratch() {
                let mut file = OpenOptions::new().write(true).open(&source).unwrap();
                file.seek(SeekFrom::Start(0x1800)).unwrap();
                file.write_all(&[0x55]).unwrap();
                mutated = true;
            }
            false
        })
        .is_err()
    );
    assert!(mutated);
    assert!(!failed.exists());
    assert!(!temp.has_scratch());
    assert_eq!(fs::read(Path::new(&original)).unwrap(), original_bytes);
}
