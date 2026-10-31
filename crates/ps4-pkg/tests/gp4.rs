use ps4_pkg::gp4::{MAX_DEPTH, MAX_NODES, MAX_XML_SIZE, Project, Settings};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = if std::path::Path::new("/tmp/opencode").is_dir() {
            PathBuf::from("/tmp/opencode")
        } else {
            std::env::temp_dir()
        };
        let path = base.join(format!(
            "pkg-gp4-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("game")).unwrap();
        fs::create_dir(path.join("game/sce_sys")).unwrap();
        fs::create_dir(path.join("game/empty & dir")).unwrap();
        fs::write(path.join("game/eboot.bin"), b"synthetic, not executable").unwrap();
        fs::write(path.join("game/a&b's.bin"), b"").unwrap();
        fs::write(
            path.join("game/sce_sys/param.sfo"),
            sfo("gd", "CUSA00000", "01.23"),
        )
        .unwrap();
        Self(path)
    }
    fn source(&self) -> PathBuf {
        self.0.join("game")
    }
    fn location(&self) -> PathBuf {
        self.0.join("base.gp4")
    }
    fn project(&self) -> Project {
        Project::from_directory(&self.source(), &self.location(), settings()).unwrap()
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn settings() -> Settings {
    Settings {
        passcode: "synthetic&passcode'for\"test00000".into(),
        timestamp: "2026-10-31 12:34:56".into(),
        creation_date: Some("2024-02-29".into()),
        volume_id: Some("<&>\"' Unicode: λ".into()),
        chunk_label: "chunk & \"label\"\nnext".into(),
        scenario_label: "scenario <0>".into(),
    }
}

#[cfg(unix)]
#[test]
fn prepared_gp4_places_resources_and_preserves_bytes_without_pkg_claims() {
    use ps4_pkg::authoring::{Placement, PreparedProject};
    let tree = Tree::new();
    fs::write(tree.source().join("sce_sys/keystone"), [7; 96]).unwrap();
    fs::write(
        tree.source().join("sce_sys/icon0.png"),
        b"synthetic resource; not a PNG",
    )
    .unwrap();
    fs::write(tree.source().join("boundary.bin"), vec![17; 65537]).unwrap();
    let project = tree.project();
    let plan = PreparedProject::new(&project, &tree.source(), || false).unwrap();
    assert_eq!(plan.identity().app_version, "01.23");
    assert_eq!(
        plan.resources()
            .iter()
            .filter(|r| matches!(r.placement, Placement::Container(_)))
            .count(),
        2
    );
    for (i, resource) in plan.resources().iter().enumerate() {
        let mut copied = Vec::new();
        plan.copy_resource(i, &mut copied, || false).unwrap();
        assert_eq!(
            copied,
            fs::read(tree.source().join(&resource.target)).unwrap()
        );
        if let Placement::Container(id) = resource.placement {
            assert_eq!(
                id,
                if resource.target.ends_with("param.sfo") {
                    0x1000
                } else {
                    0x1200
                }
            );
        }
    }
    for extension in ["pfs", "pfsc"] {
        let destination = tree.0.join(format!("inner.{extension}"));
        plan.write_inner_new(&destination, || false).unwrap();
        let data = fs::read(&destination).unwrap();
        assert_eq!(
            data.len() as u64,
            if extension == "pfs" {
                plan.pfs_size()
            } else {
                plan.pfsc_size()
            }
        );
        assert!(!data.windows(b"param.sfo".len()).any(|w| w == b"param.sfo"));
        assert!(!data.windows(b"icon0.png".len()).any(|w| w == b"icon0.png"));
        assert!(data.windows(b"keystone".len()).any(|w| w == b"keystone"));
        assert_eq!(
            plan.write_inner_new(&destination, || false)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(destination).unwrap(), data);
    }
    assert!(
        plan.write_inner_new(&tree.0.join("invalid.pkg"), || false)
            .is_err()
    );
    assert!(
        plan.write_inner_new(&tree.source().join("invalid.pfs"), || false)
            .is_err()
    );
    assert!(!tree.0.join("invalid.pkg").exists());
    assert!(!tree.source().join("invalid.pfs").exists());
}

#[cfg(unix)]
#[test]
fn prepared_outer_image_revalidates_sources_and_never_publishes_pkg() {
    use ps4_pkg::authoring::PreparedProject;
    let tree = Tree::new();
    fs::write(tree.source().join("sce_sys/keystone"), [7; 96]).unwrap();
    let project = tree.project();
    let plan = PreparedProject::new(&project, &tree.source(), || false).unwrap();
    let key = [0x42; 32]; // Original public synthetic test input.
    let destination = tree.0.join("outer.pfs");
    plan.write_outer_new(&destination, &key, || false).unwrap();
    let original = fs::read(&destination).unwrap();
    assert_eq!(original.len() as u64, plan.outer_pfs_size().unwrap());
    assert_eq!(u16::from_le_bytes(original[28..30].try_into().unwrap()), 13);
    assert_eq!(
        plan.write_outer_new(&destination, &key, || false)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&destination).unwrap(), original);
    for path in [
        tree.0.join("bad.pkg"),
        tree.0.join("bad.pfsc"),
        tree.source().join("bad.pfs"),
    ] {
        assert!(plan.write_outer_new(&path, &key, || false).is_err());
        assert!(!path.exists());
    }
    let changed = tree.0.join("changed.pfs");
    let mut mutated = false;
    assert!(
        plan.write_outer_new(&changed, &key, || {
            if !mutated
                && fs::read_dir(&tree.0).unwrap().any(|e| {
                    e.unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".pkg-tools-image-")
                })
            {
                fs::write(
                    tree.source().join("sce_sys/param.sfo"),
                    b"changed excluded metadata",
                )
                .unwrap();
                mutated = true;
            }
            false
        })
        .is_err()
    );
    assert!(mutated);
    assert!(!changed.exists());
    assert!(!fs::read_dir(&tree.0).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pkg-tools-image-")
    }));
    assert_eq!(fs::read(destination).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn prepared_gp4_refuses_unresolved_resources_and_source_changes() {
    use ps4_pkg::authoring::PreparedProject;
    let tree = Tree::new();
    assert!(PreparedProject::new(&tree.project(), &tree.source(), || false).is_err());
    for size in [95, 97] {
        fs::write(tree.source().join("sce_sys/keystone"), vec![7; size]).unwrap();
        assert!(PreparedProject::new(&tree.project(), &tree.source(), || false).is_err());
    }
    fs::write(tree.source().join("sce_sys/keystone"), [7; 96]).unwrap();
    for path in [
        "npbind.dat",
        "nptitle.dat",
        "playgo-chunk.dat",
        "unknown.bin",
    ] {
        let path = tree.source().join("sce_sys").join(path);
        fs::write(&path, []).unwrap();
        assert!(PreparedProject::new(&tree.project(), &tree.source(), || false).is_err());
        fs::remove_file(path).unwrap();
    }
    let project = tree.project();
    assert!(PreparedProject::new(&project, &tree.source().join("sce_sys"), || false).is_err());
    for target in [
        "eboot.bin",
        "a&b's.bin",
        "sce_sys/param.sfo",
        "sce_sys/keystone",
    ] {
        let plan = PreparedProject::new(&project, &tree.source(), || false).unwrap();
        let path = tree.source().join(target);
        let before = fs::read(&path).unwrap();
        fs::write(&path, vec![8; before.len()]).unwrap();
        let destination = tree.0.join("changed.pfs");
        assert!(plan.write_inner_new(&destination, || false).is_err());
        assert!(!destination.exists());
        fs::write(path, before).unwrap();
    }
    let plan = PreparedProject::new(&project, &tree.source(), || false).unwrap();
    let path = tree.source().join("eboot.bin");
    fs::rename(&path, tree.0.join("original-eboot")).unwrap();
    std::os::unix::fs::symlink(tree.0.join("original-eboot"), &path).unwrap();
    assert!(
        plan.write_inner_new(&tree.0.join("symlink.pfs"), || false)
            .is_err()
    );
    assert!(!tree.0.join("symlink.pfs").exists());
}

#[cfg(unix)]
#[test]
fn prepared_gp4_cancels_and_detects_changes_before_publication_cleans_scratch() {
    use ps4_pkg::authoring::PreparedProject;
    let tree = Tree::new();
    fs::write(tree.source().join("sce_sys/keystone"), [7; 96]).unwrap();
    let project = tree.project();
    assert!(PreparedProject::new(&project, &tree.source(), || true).is_err());
    let plan = PreparedProject::new(&project, &tree.source(), || false).unwrap();
    let destination = tree.0.join("cancelled.pfs");
    // Mutation during output must prevent publication even for excluded metadata.
    let mut changed = false;
    assert!(
        plan.write_inner_new(&destination, || {
            let scratch = fs::read_dir(&tree.0).unwrap().any(|e| {
                e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pkg-tools-image-")
            });
            if scratch && !changed {
                fs::write(tree.source().join("sce_sys/param.sfo"), b"changed").unwrap();
                changed = true;
            }
            false
        })
        .is_err()
    );
    assert!(changed);
    assert!(!destination.exists());
    assert!(!fs::read_dir(&tree.0).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pkg-tools-image-")
    }));
    fs::write(
        tree.source().join("sce_sys/param.sfo"),
        sfo("gd", "CUSA00000", "01.23"),
    )
    .unwrap();
    let plan = PreparedProject::new(&project, &tree.source(), || false).unwrap();
    assert_eq!(
        plan.write_inner_new(&destination, || fs::read_dir(&tree.0).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pkg-tools-image-")))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Interrupted
    );
    assert!(!destination.exists());
    assert!(!fs::read_dir(&tree.0).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pkg-tools-image-")
    }));
}

#[cfg(unix)]
#[test]
fn source_root_refuses_symlinks_parents_special_files_and_escape() {
    let tree = Tree::new();
    let source = pkg_fs::SourceRoot::open(&tree.source()).unwrap();
    assert!(source.open_file(std::path::Path::new("eboot.bin")).is_ok());
    for path in ["", ".", "../game/eboot.bin", "/etc/passwd", "sce_sys"] {
        assert!(source.open_file(std::path::Path::new(path)).is_err());
    }
    std::os::unix::fs::symlink(tree.source().join("sce_sys"), tree.source().join("link")).unwrap();
    assert!(
        source
            .open_file(std::path::Path::new("link/param.sfo"))
            .is_err()
    );
    assert!(pkg_fs::SourceRoot::open(&tree.source().join("link")).is_err());
    std::os::unix::fs::symlink(
        tree.source().join("eboot.bin"),
        tree.source().join("linked-file"),
    )
    .unwrap();
    assert!(
        source
            .open_file(std::path::Path::new("linked-file"))
            .is_err()
    );
}

#[test]
fn authoring_inventory_preserves_sources_and_reports_real_build_gates() {
    use ps4_pkg::authoring::{self, ResourceKind};
    let tree = Tree::new();
    let source = tree.source();
    let original_sfo = fs::read(source.join("sce_sys/param.sfo")).unwrap();
    let project = tree.project();
    let check = authoring::preflight(&project, &source, || false).unwrap();
    assert_eq!(check.resources.len(), 3);
    assert_eq!(check.directory_count, 2);
    assert_eq!(check.identity.app_version, "01.23");
    assert_eq!(check.source_bytes, original_sfo.len() as u64 + 25);
    assert!(
        check
            .input_blockers
            .iter()
            .any(|b| b.contains("missing sce_sys/keystone"))
    );
    assert!(
        authoring::WRITER_BLOCKERS
            .iter()
            .any(|b| b.contains("not implemented"))
    );

    fs::create_dir(source.join("sce_sys/trophy")).unwrap();
    fs::create_dir(source.join("sce_sys/app")).unwrap();
    for (path, bytes) in [
        ("keystone", vec![7; 96]),
        ("npbind.dat", vec![]),
        ("nptitle.dat", vec![]),
        ("trophy/trophy00.trp", vec![]),
        ("playgo-chunk.dat", vec![]),
        ("app/playgo-chunk.dat", vec![]),
        ("unknown.bin", vec![]),
    ] {
        fs::write(source.join("sce_sys").join(path), bytes).unwrap();
    }
    let project = tree.project();
    let check = authoring::preflight(&project, &source, || false).unwrap();
    assert_eq!(check.input_blockers.len(), 6);
    for (path, kind) in [
        ("eboot.bin", ResourceKind::Application),
        ("sce_sys/param.sfo", ResourceKind::ParamSfo),
        ("sce_sys/keystone", ResourceKind::Keystone),
        ("sce_sys/npbind.dat", ResourceKind::NpTrophy),
        ("sce_sys/trophy/trophy00.trp", ResourceKind::NpTrophy),
        ("sce_sys/playgo-chunk.dat", ResourceKind::PlayGo),
        ("sce_sys/app/playgo-chunk.dat", ResourceKind::PlayGo),
        ("sce_sys/unknown.bin", ResourceKind::UnclassifiedSystem),
    ] {
        assert_eq!(
            check
                .resources
                .iter()
                .find(|r| r.source.target == path)
                .unwrap()
                .kind,
            kind
        );
    }
    fs::write(source.join("sce_sys/keystone"), [7; 95]).unwrap();
    let check = authoring::preflight(&project, &source, || false).unwrap();
    assert!(
        check
            .input_blockers
            .iter()
            .any(|b| b.contains("exactly 96 bytes"))
    );
    assert_eq!(
        fs::read(source.join("sce_sys/param.sfo")).unwrap(),
        original_sfo
    );
    assert!(!tree.location().exists());
    assert!(!format!("{check:?}").contains(&project.settings().passcode));
}

#[test]
fn authoring_inventory_refuses_unapproved_sources_and_supports_cancellation() {
    use ps4_pkg::authoring::preflight;
    let tree = Tree::new();
    let project = tree.project();
    assert!(preflight(&project, &tree.source().join("sce_sys"), || false).is_err());
    assert_eq!(
        preflight(&project, &tree.source(), || true)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Interrupted
    );
    let mut calls = 0;
    assert_eq!(
        preflight(&project, &tree.source(), || {
            calls += 1;
            calls > 2
        })
        .unwrap_err()
        .kind(),
        std::io::ErrorKind::Interrupted
    );
    fs::remove_file(tree.source().join("eboot.bin")).unwrap();
    assert!(preflight(&project, &tree.source(), || false).is_err());
    assert!(!tree.location().exists());
}

/// Run only through the pinned synthetic harness; files contain local passcodes.
#[test]
#[ignore = "requires check-authoring.py generated pinned-reference roundtrip"]
fn pinned_reference_roundtrip() {
    let root = PathBuf::from(
        std::env::var_os("PKG_TOOLS_GP4_REFERENCE_DIR").expect("reference output root required"),
    );
    for prefix in ["", "settings-"] {
        let native = Project::parse(
            &fs::read_to_string(root.join(format!("{prefix}generated.gp4"))).unwrap(),
            &root.join(format!("{prefix}generated.gp4")),
        )
        .unwrap();
        let reference = Project::parse(
            &fs::read_to_string(root.join(format!("{prefix}reference.gp4"))).unwrap(),
            &root.join(format!("{prefix}reference.gp4")),
        )
        .unwrap();
        assert_eq!(native.files(), reference.files());
        assert_eq!(native.directories(), reference.directories());
        assert_eq!(native.content_id(), reference.content_id());
        // Avoid printing either passcode even on assertion failure.
        assert!(native.settings().passcode == reference.settings().passcode);
        assert_eq!(native.settings().timestamp, reference.settings().timestamp);
        assert_eq!(
            native.settings().creation_date,
            reference.settings().creation_date
        );
        assert_eq!(native.settings().volume_id, reference.settings().volume_id);
        assert_eq!(
            native.settings().chunk_label,
            reference.settings().chunk_label
        );
        assert_eq!(
            native.settings().scenario_label,
            reference.settings().scenario_label
        );
        let before = native.preflight(&root.join("gp4-source")).unwrap();
        let after = reference.preflight(&root.join("gp4-source")).unwrap();
        assert_eq!(before.identity, after.identity);
        assert!(native.to_xml().unwrap() == reference.to_xml().unwrap());
    }
}

fn sfo(category: &str, title: &str, app_ver: &str) -> Vec<u8> {
    let fields = [
        ("CATEGORY", category),
        ("CONTENT_ID", "ZZ0000-CUSA00000_00-SYNTHETIC0000000"),
        ("TITLE_ID", title),
        ("APP_VER", app_ver),
        ("VERSION", "01.00"),
    ];
    let raw: Vec<_> = fields
        .iter()
        .map(|(_, value)| format!("{value}\0").into_bytes())
        .collect();
    let entries = fields
        .iter()
        .zip(&raw)
        .map(|((key, value), raw)| psf::Entry {
            key: key.as_bytes(),
            format: 0x204,
            value: psf::Value::Text(value.as_bytes()),
            raw,
            max_len: raw.len() as u32,
            padding: &[],
        })
        .collect();
    psf::serialize(&psf::Sfo {
        version: 0x101,
        entries,
    })
    .unwrap()
}

#[test]
fn generation_escaping_and_semantic_roundtrip() {
    let tree = Tree::new();
    let project = tree.project();
    let xml = project.to_xml().unwrap();
    assert!(xml.contains("a&amp;b&apos;s.bin"));
    assert!(xml.contains("&lt;&amp;&gt;&quot;&apos;"));
    let parsed = Project::parse(&xml, &tree.location()).unwrap();
    assert_eq!(parsed.files(), project.files());
    assert_eq!(parsed.directories(), project.directories());
    assert_eq!(parsed.settings().passcode, settings().passcode);
    assert_eq!(parsed.settings().chunk_label, settings().chunk_label);
    assert_eq!(parsed.settings().volume_id, settings().volume_id);
    assert_eq!(parsed.settings().creation_date, settings().creation_date);
    let check = parsed.preflight(&tree.source()).unwrap();
    assert_eq!(check.identity.title_id, "CUSA00000");
    assert_eq!(check.identity.app_version, "01.23");
    assert_eq!(check.identity.version, "01.00");
    assert!(parsed.directories().contains("empty & dir"));
    assert!(
        check
            .sources
            .iter()
            .all(|s| !s.absolute_reference && !s.outside_project_directory)
    );
    parsed.write_new(&tree.source()).unwrap();
    assert_eq!(fs::read_to_string(tree.location()).unwrap(), xml);
    assert_eq!(
        parsed.write_new(&tree.source()).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read_to_string(tree.location()).unwrap(), xml);
    assert_eq!(
        fs::read(tree.source().join("eboot.bin")).unwrap(),
        b"synthetic, not executable"
    );
    assert!(!fs::read_dir(&tree.0).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pkg-tools")
    }));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(tree.location()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn resolution_uses_project_location_and_explicit_root_approval() {
    let tree = Tree::new();
    let projects = tree.0.join("projects");
    fs::create_dir(&projects).unwrap();
    let location = projects.join("game.gp4");
    let project = Project::from_directory(&tree.source(), &location, settings()).unwrap();
    assert!(
        project
            .files()
            .iter()
            .all(|f| f.source.starts_with("../game/"))
    );
    let parsed = Project::parse(&project.to_xml().unwrap(), &location).unwrap();
    assert!(parsed.preflight(&projects).is_err());
    assert!(
        parsed
            .preflight(&tree.source())
            .unwrap()
            .sources
            .iter()
            .all(|s| s.outside_project_directory && s.resolved.starts_with(tree.source()))
    );
    let xml = parsed.to_xml().unwrap().replace(
        "../game/eboot.bin",
        tree.source().join("eboot.bin").to_str().unwrap(),
    );
    let absolute = Project::parse(&xml, &location).unwrap();
    assert!(
        absolute
            .preflight(&tree.source())
            .unwrap()
            .sources
            .iter()
            .any(|s| s.absolute_reference)
    );
    // Test process CWD is the workspace, not either project/source directory.
    assert_ne!(std::env::current_dir().unwrap(), projects);
    assert!(Project::parse(&xml, std::path::Path::new("relative.gp4")).is_err());
    assert!(
        Project::parse(&xml, &tree.source().join("bad.gp4"))
            .unwrap()
            .write_new(&tree.source())
            .is_err()
    );
}

#[test]
fn rejects_xml_limits_dtd_and_malformed_documents() {
    let tree = Tree::new();
    let xml = tree.project().to_xml().unwrap();
    for malformed in [
        "<psproject>",
        "<x/>",
        "<!DOCTYPE psproject SYSTEM 'file:///etc/passwd'><psproject/>",
        "<!DOCTYPE psproject [<!ENTITY x 'boom'>]><psproject>&x;</psproject>",
    ] {
        assert!(Project::parse(malformed, &tree.location()).is_err());
    }
    assert!(Project::parse(&" ".repeat(MAX_XML_SIZE + 1), &tree.location()).is_err());
    let deep = format!(
        "{}{}",
        "<dir targ_name='x'>".repeat(MAX_DEPTH),
        "</dir>".repeat(MAX_DEPTH)
    );
    assert!(
        Project::parse(
            &xml.replace("<rootdir>", &format!("<rootdir>{deep}")),
            &tree.location()
        )
        .is_err()
    );
    let nodes = format!("<x>{}</x>", "<n/>".repeat(MAX_NODES as usize));
    assert!(Project::parse(&nodes, &tree.location()).is_err());
    let too_many = "<file targ_path='duplicate' orig_path='game/eboot.bin'/>".repeat(32_769);
    let error = Project::parse(
        &xml.replace("</files>", &format!("{too_many}</files>")),
        &tree.location(),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("32768"));
}

#[test]
fn unsupported_settings_are_named_and_never_silently_dropped() {
    let tree = Tree::new();
    let xml = tree.project().to_xml().unwrap();
    for (from, to, name) in [
        ("pkg_ps4_app", "pkg_ps4_patch", "volume_type"),
        ("pkg_ps4_app", "pkg_ps4_remaster", "volume_type"),
        ("pkg_ps4_app", "pkg_ps4_delta", "volume_type"),
        ("img_no=\"0\"", "img_no=\"1\"", "img_no"),
        ("<package ", "<package app_path=\"base.pkg\" ", "app_path"),
        (
            "<package ",
            "<package entitlement_key=\"x\" ",
            "entitlement_key",
        ),
        (
            "<file ",
            "<file pfs_compression=\"enable\" ",
            "pfs_compression",
        ),
        ("<chunk_info ", "<chunk_info language=\"en\" ", "language"),
        ("</volume>", "<delta_info/></volume>", "delta_info"),
        (
            "</chunk_info>",
            "<scenarios_info/></chunk_info>",
            "scenarios_info",
        ),
        ("layer_no=\"0\"", "layer_no=\"1\"", "layer_no"),
        (
            "c_date=\"2024-02-29\"",
            "c_date=\"actual_datetime\"",
            "c_date",
        ),
    ] {
        let error = Project::parse(&xml.replace(from, to), &tree.location())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains(name), "{error} did not name {name}");
    }
    for date in [
        "2023-02-29 00:00:00",
        "2024-13-01 00:00:00",
        "2026-01-01 24:00:00",
        "2026-01-01T00:00:00Z",
    ] {
        assert!(
            Project::parse(&xml.replace("2026-10-31 12:34:56", date), &tree.location()).is_err()
        );
    }
    for change in [
        xml.replace("</volume>", "</volume><volume/>"),
        xml.replace("</chunks>", "<chunk id=\"0\"/></chunks>"),
        xml.replace("</scenario>", "<!--split-->1</scenario>"),
        xml.replace("orig_path=\"game/eboot.bin\"", ""),
    ] {
        assert!(Project::parse(&change, &tree.location()).is_err());
    }
}

#[test]
fn destination_conflicts_and_unsafe_paths_fail() {
    let tree = Tree::new();
    let xml = tree.project().to_xml().unwrap();
    for target in [
        "../escape",
        "/absolute",
        "C:/drive",
        "a\\b",
        "a//b",
        "a/./b",
        "CON",
        "trail.",
        "sce_sys",
        "SCE_SYS/param.sfo",
        "empty &amp; dir",
        "eboot.bin",
    ] {
        let changed = xml.replace(
            "targ_path=\"a&amp;b&apos;s.bin\"",
            &format!("targ_path=\"{target}\""),
        );
        assert!(
            Project::parse(&changed, &tree.location()).is_err(),
            "accepted {target}"
        );
    }
    assert!(
        Project::parse(
            &xml.replace("</rootdir>", "<dir targ_name=\"sce_sys\"/></rootdir>"),
            &tree.location()
        )
        .is_err()
    );
    assert!(
        Project::parse(
            &xml.replace("targ_name=\"sce_sys\"", "targ_name=\"other\""),
            &tree.location()
        )
        .is_err()
    );
    fs::write(tree.source().join("EBOOT.BIN"), b"case collision").unwrap();
    assert!(Project::from_directory(&tree.source(), &tree.location(), settings()).is_err());
}

#[test]
fn sfo_identity_not_directory_name_and_sources_are_not_modified() {
    let tree = Tree::new();
    for (category, title, version) in [
        ("gp", "CUSA00000", "01.23"),
        ("gd", "CUSA99999", "01.23"),
        ("gd", "CUSA00000", "1.0"),
    ] {
        let bytes = sfo(category, title, version);
        fs::write(tree.source().join("sce_sys/param.sfo"), &bytes).unwrap();
        assert!(Project::from_directory(&tree.source(), &tree.location(), settings()).is_err());
        assert_eq!(
            fs::read(tree.source().join("sce_sys/param.sfo")).unwrap(),
            bytes
        );
    }
    fs::write(
        tree.source().join("sce_sys/param.sfo"),
        sfo("gd", "CUSA00000", "01.23"),
    )
    .unwrap();
    let xml = tree
        .project()
        .to_xml()
        .unwrap()
        .replace("ZZ0000-CUSA00000", "ZZ0000-CUSA99999");
    assert!(
        Project::parse(&xml, &tree.location())
            .unwrap()
            .preflight(&tree.source())
            .is_err()
    );
    fs::remove_file(tree.source().join("eboot.bin")).unwrap();
    assert!(Project::from_directory(&tree.source(), &tree.location(), settings()).is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_special_files_and_output_aliases_are_rejected() {
    use std::os::unix::fs::symlink;
    let tree = Tree::new();
    let xml = tree.project().to_xml().unwrap();
    symlink(tree.source().join("eboot.bin"), tree.source().join("link")).unwrap();
    assert!(Project::from_directory(&tree.source(), &tree.location(), settings()).is_err());
    assert!(
        Project::parse(
            &xml.replace("game/eboot.bin", "game/link"),
            &tree.location()
        )
        .unwrap()
        .preflight(&tree.source())
        .is_err()
    );
    fs::remove_file(tree.source().join("link")).unwrap();
    symlink(tree.source(), tree.0.join("linkdir")).unwrap();
    for source in ["linkdir/eboot.bin", "linkdir/../game/eboot.bin"] {
        assert!(
            Project::parse(&xml.replace("game/eboot.bin", source), &tree.location())
                .unwrap()
                .preflight(&tree.source())
                .is_err()
        );
    }
    assert!(
        Project::from_directory(&tree.0.join("linkdir"), &tree.location(), settings()).is_err()
    );
    assert!(
        Project::from_directory(
            &tree.0.join("linkdir/../game"),
            &tree.location(),
            settings()
        )
        .is_err()
    );
    symlink(tree.source().join("eboot.bin"), tree.location()).unwrap();
    assert!(tree.project().write_new(&tree.source()).is_err());
    assert_eq!(
        fs::read(tree.source().join("eboot.bin")).unwrap(),
        b"synthetic, not executable"
    );
    fs::remove_file(tree.location()).unwrap();
    fs::hard_link(tree.source().join("eboot.bin"), tree.location()).unwrap();
    assert!(tree.project().write_new(&tree.source()).is_err());
    assert_eq!(
        fs::read(tree.location()).unwrap(),
        b"synthetic, not executable"
    );
    let socket = std::os::unix::net::UnixListener::bind(tree.source().join("socket")).unwrap();
    assert!(
        Project::from_directory(&tree.source(), &tree.0.join("other.gp4"), settings()).is_err()
    );
    assert!(
        Project::parse(
            &xml.replace("game/eboot.bin", "game/socket"),
            &tree.location()
        )
        .unwrap()
        .preflight(&tree.source())
        .is_err()
    );
    drop(socket);
}
