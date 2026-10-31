use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

#[test]
fn fpkg_preflight_reports_inventory_not_writer_success() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ps4-selection.pkg");
    let original = fs::read(&path).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
        .args(["fpkg", "preflight"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Package authoring inventory:"));
    assert!(text.contains("missing general digests"));
    assert!(text.contains("missing or wrong-size original sce_sys/keystone"));
    assert!(text.contains("build unavailable. No PKG built"));
    assert!(text.contains("Header/digest/NP bytes withheld"));
    assert!(!text.contains("raw_hex"));
    assert_eq!(fs::read(&path).unwrap(), original);
    let invalid = Input::new(b"invalid");
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
            .args(["fpkg", "preflight"])
            .arg(&invalid.0)
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn gp4_create_requires_explicit_settings_and_never_overwrites() {
    let input = Input::new(b"not an executable");
    let root = input.0.parent().unwrap();
    let game = root.join("not-a-title-id");
    fs::create_dir(&game).unwrap();
    fs::create_dir(game.join("sce_sys")).unwrap();
    fs::write(game.join("eboot.bin"), b"synthetic").unwrap();
    let fields = [
        ("CATEGORY", "gd"),
        ("CONTENT_ID", "ZZ0000-CUSA00000_00-SYNTHETIC0000000"),
        ("TITLE_ID", "CUSA00000"),
        ("APP_VER", "01.23"),
        ("VERSION", "01.00"),
    ];
    let bytes: Vec<_> = fields
        .iter()
        .map(|(_, value)| format!("{value}\0").into_bytes())
        .collect();
    let sfo = psf::serialize(&psf::Sfo {
        version: 0x101,
        entries: fields
            .iter()
            .zip(&bytes)
            .map(|((key, value), bytes)| psf::Entry {
                key: key.as_bytes(),
                format: 0x204,
                value: psf::Value::Text(value.as_bytes()),
                raw: bytes,
                max_len: bytes.len() as u32,
                padding: &[],
            })
            .collect(),
    })
    .unwrap();
    fs::write(game.join("sce_sys/param.sfo"), &sfo).unwrap();
    let passcode = root.join("passcode");
    fs::write(&passcode, b"0123456789abcdef0123456789abcdef\n").unwrap();
    let output = root.join("game.gp4");
    let run = |secret: &std::path::Path, timestamp: &str| {
        Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
            .current_dir(root)
            .args(["gp4", "create"])
            .arg(&game)
            .arg(&output)
            .arg("--passcode-file")
            .arg(secret)
            .args(["--timestamp", timestamp])
            .output()
            .unwrap()
    };
    assert!(!run(&passcode, "not a timestamp").status.success());
    assert!(!output.exists());
    fs::write(game.join("passcode"), b"0123456789abcdef0123456789abcdef").unwrap();
    assert!(
        !run(&game.join("passcode"), "2026-10-31 00:00:00")
            .status
            .success()
    );
    fs::remove_file(game.join("passcode")).unwrap();
    let result = run(&passcode, "2026-10-31 00:00:00");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("CUSA00000 (APP_VER 01.23, VERSION 01.00)")
    );
    let xml = fs::read(&output).unwrap();
    assert!(!run(&passcode, "2026-10-31 00:00:00").status.success());
    assert_eq!(fs::read(&output).unwrap(), xml);
    assert_eq!(fs::read(game.join("sce_sys/param.sfo")).unwrap(), sfo);
    #[cfg(unix)]
    {
        let image = root.join("inner.pfsc");
        let image_project = root.join("image.gp4");
        let build_image = |destination: &std::path::Path| {
            Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
                .current_dir(&game)
                .args(["gp4", "image"])
                .arg(&image_project)
                .arg(destination)
                .arg("--source-root")
                .arg(&game)
                .output()
                .unwrap()
        };
        fs::write(&image_project, &xml).unwrap();
        assert!(!build_image(&image).status.success());
        assert!(!image.exists());
        fs::remove_file(&image_project).unwrap();
        fs::write(game.join("sce_sys/keystone"), [7; 96]).unwrap();
        assert!(
            Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
                .args(["gp4", "create"])
                .arg(&game)
                .arg(&image_project)
                .arg("--passcode-file")
                .arg(&passcode)
                .args(["--timestamp", "2026-10-31 00:00:00"])
                .output()
                .unwrap()
                .status
                .success()
        );
        let result = build_image(&image);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let text = String::from_utf8(result.stdout).unwrap();
        assert!(text.contains("Scratch requirement:"));
        assert!(text.contains("Intermediate image published. Not a PKG"));
        assert!(!text.contains("0123456789abcdef0123456789abcdef"));
        assert_eq!(&fs::read(&image).unwrap()[..4], b"PFSC");
        assert!(!build_image(&image).status.success());
        assert!(!build_image(&root.join("invalid.pkg")).status.success());
        assert!(!root.join("invalid.pkg").exists());
        assert_eq!(fs::read(game.join("sce_sys/param.sfo")).unwrap(), sfo);
        assert_eq!(fs::read(game.join("sce_sys/keystone")).unwrap(), [7; 96]);
    }
    let preflight = |root: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
            // References must resolve against GP4 location, not this CWD.
            .current_dir(&game)
            .args(["gp4", "preflight"])
            .arg(&output)
            .arg("--source-root")
            .arg(root)
            .output()
            .unwrap()
    };
    let result = preflight(&game);
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("missing sce_sys/keystone"));
    assert!(text.contains("build unavailable. No PKG built"));
    assert!(text.contains("provenance/distribution review is not cleared"));
    assert!(!text.contains("0123456789abcdef0123456789abcdef"));
    assert!(!preflight(&game.join("sce_sys")).status.success());
    assert_eq!(fs::read(&output).unwrap(), xml);
    assert_eq!(fs::read(game.join("sce_sys/param.sfo")).unwrap(), sfo);
}

#[test]
fn trophy_command_handles_both_platforms_empty_sets_and_invalid_arguments() {
    for name in ["ps3-list-explicit.pkg", "ps4-selection.pkg"] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name);
        let original = fs::read(&path).unwrap();
        for json in [false, true] {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkg-tools"));
            cmd.arg("trophies").arg(&path);
            if json {
                cmd.arg("--json");
            }
            let output = cmd.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if json {
                let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(doc, serde_json::json!({"sets": []}));
            } else {
                assert_eq!(output.stdout, b"No trophy sets found.\n");
            }
        }
        assert_eq!(fs::read(&path).unwrap(), original);
        let invalid = Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
            .arg("trophies")
            .arg(&path)
            .arg("--invalid")
            .output()
            .unwrap();
        assert!(!invalid.status.success());
    }
    let input = Input::new(b"invalid package");
    let output = Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
        .arg("trophies")
        .arg(&input.0)
        .arg("--json")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

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
fn ps3_debug_inspection_extraction_and_overwrite_refusal() {
    // Independent Python struct/hashlib fixture: PARAM.SFO with TITLE=Synthetic.
    let hex: String = include_str!("../../../tests/fixtures/ps3-debug.hex")
        .split_whitespace()
        .collect();
    let data: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let input = Input::new(&data);
    let result = input.inspect(true);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(doc["format"], "ps3-pkg");
    assert_eq!(doc["header"]["release_type"], 0);
    assert_eq!(doc["sfo"]["entries"][0]["value"], "Synthetic");
    assert_eq!(doc["entries"][0]["path"], "PARAM.SFO");
    let human = input.inspect(false);
    assert!(human.status.success());
    assert!(!String::from_utf8_lossy(&human.stdout).contains("FPKG"));
    let destination = input.0.parent().unwrap().join("out");
    for success in [true, false] {
        let result = Command::new(env!("CARGO_BIN_EXE_pkg-tools"))
            .arg("extract")
            .arg(&input.0)
            .arg(&destination)
            .output()
            .unwrap();
        assert_eq!(result.status.success(), success);
    }
    let bytes = fs::read(destination.join("PARAM.SFO")).unwrap();
    assert_eq!(
        psf::parse(&bytes).unwrap().get(b"TITLE").unwrap().value,
        psf::Value::Text(b"Synthetic")
    );
    assert_eq!(fs::read(&input.0).unwrap(), data);
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
        (b"\x7fPKG".as_slice(), "malformed"),
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
fn extraction_rejects_truncated_packages_before_creating_output() {
    for magic in [b"\x7fPKG", b"\x7fCNT"] {
        let input = Input::new(magic);
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
                .contains("truncated")
        );
    }
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
