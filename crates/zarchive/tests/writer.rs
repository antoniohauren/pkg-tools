use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use zarchive::Writer;

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "zar-test-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn footer_and_spilled_records() {
    let temp = Temp::new();
    let path = temp.0.join("test.zar");
    let mut w = Writer::create(&path).unwrap();
    w.add_directory("nested").unwrap();
    w.add_file("nested/empty", 0, &b""[..]).unwrap();
    w.add_file(
        "payload",
        17 * 65536 + 1,
        io::repeat(42).take(17 * 65536 + 1),
    )
    .unwrap();
    w.finish().unwrap();
    let mut bytes = fs::read(path).unwrap();
    let f = bytes.len() - 144;
    let get = |i| u64::from_be_bytes(bytes[f + i..f + i + 8].try_into().unwrap());
    assert_eq!(get(24), 80);
    assert_eq!(get(16) % 8, 0);
    assert_eq!(get(128), bytes.len() as u64);
    let hash = bytes[f + 96..f + 128].to_vec();
    bytes[f + 96..f + 128].fill(0);
    assert_eq!(Sha256::digest(&bytes).as_slice(), hash);
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 1);
}

#[test]
fn invalid_paths_sizes_and_poisoning() {
    let temp = Temp::new();
    for path in [
        "", "/a", "a/", "a//b", "..", "a/../b", "a\\b", "a\0b", "C:x",
    ] {
        let output = temp.0.join("bad.zar");
        let mut w = Writer::create(&output).unwrap();
        assert!(w.add_directory(path).is_err(), "{path:?}");
        assert!(w.finish().is_err());
        assert!(!output.exists());
    }
    for (size, bytes) in [(2, &b"x"[..]), (0, &b"x"[..]), (1 << 48, &b""[..])] {
        let mut w = Writer::create(temp.0.join("bad.zar")).unwrap();
        assert!(w.add_file("file", size, bytes).is_err());
        assert!(w.add_directory("later").is_err());
        assert!(w.finish().is_err());
    }
    let mut w = Writer::create(temp.0.join("bad.zar")).unwrap();
    w.add_directory("Dir").unwrap();
    assert!(w.add_file("dir/file", 1, &b"x"[..]).is_err());
    drop(w);
    let mut w = Writer::create(temp.0.join("bad.zar")).unwrap();
    w.add_directory("Dir").unwrap();
    assert!(w.add_directory("DIR").is_err());
    drop(w);
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
}

#[test]
fn empty_abort_and_destination_race() {
    let temp = Temp::new();
    let path = temp.0.join("out.zar");
    let mut w = Writer::create(&path).unwrap();
    w.add_file("empty", 0, io::empty()).unwrap();
    assert!(w.finish().is_err());
    assert!(!path.exists());
    let mut w = Writer::create(&path).unwrap();
    w.add_file("file", 1, &b"x"[..]).unwrap();
    fs::write(&path, b"existing").unwrap();
    assert_eq!(w.finish().unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path).unwrap(), b"existing");
    assert!(Writer::create(&path).is_err());
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 1);
}

#[test]
fn directory_rejects_internal_output_and_links() {
    let temp = Temp::new();
    let source = temp.0.join("source");
    fs::create_dir(&source).unwrap();
    assert!(zarchive::pack_directory(&source, source.join("out.zar")).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/dev/zero", source.join("link")).unwrap();
        assert!(zarchive::pack_directory(&source, temp.0.join("out.zar")).is_err());
        assert!(!temp.0.join("out.zar").exists());
    }
}

#[test]
fn read_failure_after_output_prevents_publication() {
    struct Broken(bool);
    impl Read for Broken {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::other("injected input failure"));
            }
            self.0 = true;
            bytes.fill(42);
            Ok(bytes.len())
        }
    }
    let temp = Temp::new();
    let output = temp.0.join("out.zar");
    let mut w = Writer::create(&output).unwrap();
    assert!(w.add_file("file", 65537, Broken(false)).is_err());
    assert!(w.finish().is_err());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
    let mut w = Writer::create(&output).unwrap();
    assert!(w.add_directory(&"x".repeat(128)).is_err());
}
