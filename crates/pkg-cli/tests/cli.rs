use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Input(PathBuf);
impl Input {
    fn new(data: &[u8]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pkg-tools-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("input with spaces.pkg");
        fs::write(&path, data).unwrap();
        Self(path)
    }
    fn inspect(&self, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkg-tools"));
        cmd.arg("inspect").arg(&self.0);
        if json {
            cmd.arg("--json");
        }
        cmd.output().unwrap()
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        fs::remove_dir_all(self.0.parent().unwrap()).unwrap();
    }
}

fn sfo() -> Vec<u8> {
    let mut data = Vec::from(*b"\0PSF");
    for n in [0x101u32, 36, 42, 1] {
        data.extend(n.to_le_bytes());
    }
    data.extend(0u16.to_le_bytes());
    data.extend(0x204u16.to_le_bytes());
    for n in [5u32, 5, 0] {
        data.extend(n.to_le_bytes());
    }
    data.extend(b"TITLE\0A\"\nB\0");
    data
}

#[test]
fn detects_sfo_by_magic_and_escapes_output() {
    let input = Input::new(&sfo());
    let output = input.inspect(true);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["format"], "sfo");
    assert_eq!(doc["sfo"]["entries"][0]["value"], "A\"\nB");
    let human = input.inspect(false);
    assert!(human.status.success());
    assert!(
        String::from_utf8(human.stdout)
            .unwrap()
            .contains("A\\\"\\nB")
    );
}

#[test]
fn malformed_unsupported_and_missing_inputs_exit_unsuccessfully() {
    for (data, message) in [
        (b"\x7fPKG".as_slice(), "unsupported"),
        (b"\x7fCNT", "malformed"),
        (b"", "malformed"),
    ] {
        let result = Input::new(data).inspect(true);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8(result.stderr).unwrap().contains(message));
    }
    let input = Input::new(b"");
    fs::remove_file(&input.0).unwrap();
    assert!(!input.inspect(true).status.success());
    for args in [vec![], vec!["extract", "a"], vec!["inspect", "a", "--typo"]] {
        assert!(
            !Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}

#[test]
fn conversion_rejects_unsupported_inputs_and_bad_options_without_output() {
    let input = Input::new(b"\x7fPKG");
    let destination = input.0.parent().unwrap().join("Game.zar");
    for extra in [vec![], vec!["--typo", "update.pkg"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
            .arg("convert")
            .arg(&input.0)
            .arg(&destination)
            .args(extra)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!destination.exists());
        assert!(!destination.with_file_name("Game-UPDATE.zar").exists());
        assert_eq!(fs::read(&input.0).unwrap(), b"\x7fPKG");
    }
}

#[test]
fn extraction_rejects_ps3_before_creating_output() {
    let input = Input::new(b"\x7fPKG");
    let output = input.0.parent().unwrap().join("output");
    let result = Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
        .arg("extract")
        .arg(&input.0)
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("unsupported")
    );
}

#[test]
fn encrypted_sfo_reports_partial_inspection() {
    let mut data = vec![0u8; 0x1200];
    data[..4].copy_from_slice(b"\x7fCNT");
    for (offset, value) in [
        (0x10, 1u32),
        (0x18, 0x1100),
        (0x1100, 0x1000),
        (0x1108, 0x8000_0000),
        (0x110c, 0x3000),
        (0x1110, 0x1120),
        (0x1114, 16),
    ] {
        data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    data[0x430..0x438].copy_from_slice(&0x1200u64.to_be_bytes());
    let result = Input::new(&data).inspect(true);
    assert!(result.status.success());
    let doc: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(doc["fpkg_status"], "unverified");
    assert_eq!(doc["sfo"]["status"], "decryption_unavailable");
    assert_eq!(doc["sfo"]["key_index"], 3);
}
