use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("pkg-ops-{name}-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let hex: String = include_str!("../../../tests/fixtures/ps3-debug.hex")
            .split_whitespace()
            .collect();
        let bytes: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        fs::write(root.join("input.pkg"), bytes).unwrap();
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn extraction_progress_overwrite_refusal_and_cancellation() {
    let fixture = Fixture::new("extract");
    let input = fixture.0.join("input.pkg");
    let original = fs::read(&input).unwrap();
    let output = fixture.0.join("output");
    let cancelled = AtomicBool::new(false);
    let mut progress = Vec::new();
    pkg_ops::extract(&input, &output, &cancelled, |w, t| progress.push((w, t))).unwrap();
    assert_eq!(progress.first().unwrap().0, 0);
    let (written, total) = *progress.last().unwrap();
    assert!(total > 0);
    assert_eq!(written, total);
    assert!(progress.windows(2).all(|p| p[0].0 <= p[1].0));
    let sfo = fs::read(output.join("PARAM.SFO")).unwrap();
    assert!(pkg_ops::extract(&input, &output, &cancelled, |_, _| {}).is_err());
    assert_eq!(fs::read(output.join("PARAM.SFO")).unwrap(), sfo);

    let partial = fixture.0.join("partial");
    let error = pkg_ops::extract(&input, &partial, &cancelled, |_, _| {
        cancelled.store(true, Ordering::Relaxed);
    })
    .unwrap_err();
    assert!(pkg_ops::was_cancelled(error.as_ref()));
    assert!(error.to_string().contains(partial.to_str().unwrap()));
    assert!(partial.join(".pkg-tools-incomplete").exists());
    assert_eq!(fs::read(input).unwrap(), original);
}

#[test]
fn liberation_package_and_folder_dispatch_preserve_cancellation() {
    let fixture = Fixture::new("liberate");
    let input = fixture.0.join("input.pkg");
    let rap = fixture.0.join("license.rap");
    fs::write(&rap, [0; 16]).unwrap();
    let folder = fixture.0.join("folder");
    fs::create_dir(&folder).unwrap();
    let id = b"UP0001-TEST00001_00-0000000000000000";
    let mut sfo = b"\0PSF".to_vec();
    for value in [0x101u32, 36, 47, 1] {
        sfo.extend(value.to_le_bytes());
    }
    sfo.extend(0u16.to_le_bytes());
    sfo.extend(0x204u16.to_le_bytes());
    for value in [id.len() as u32 + 1, id.len() as u32 + 1, 0] {
        sfo.extend(value.to_le_bytes());
    }
    sfo.extend(b"CONTENT_ID\0");
    sfo.extend(id);
    sfo.push(0);
    fs::write(folder.join("PARAM.SFO"), sfo).unwrap();
    assert_eq!(
        pkg_ops::liberate::liberation_content_id(&folder)
            .unwrap()
            .as_bytes(),
        id
    );
    for source in [&input, &folder] {
        for directory in [false, true] {
            let output = fixture.0.join("unused-output");
            let error = pkg_ops::liberate::liberate(
                source,
                &rap,
                &output,
                directory,
                &AtomicBool::new(true),
                |_, _| panic!("cancelled liberation must not report progress"),
            )
            .unwrap_err();
            assert!(pkg_ops::was_cancelled(error.as_ref()), "{error}");
            assert!(!output.exists());
        }
    }
}
