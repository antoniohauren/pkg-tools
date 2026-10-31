use pkg_cli::convert;

use serde_json::{Value, json};
use std::{
    env,
    error::Error,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    process::ExitCode,
    sync::atomic::AtomicBool,
};

const USAGE: &str = "Usage: pkg-tools inspect INPUT.pkg [--json]\n       pkg-tools inspect PARAM.SFO [--json]\n       pkg-tools trophies INPUT.pkg [--json]\n       pkg-tools extract INPUT.pkg OUTPUT_DIR\n       pkg-tools pack INPUT_DIR OUTPUT.zar\n       pkg-tools convert GAME.pkg OUTPUT.zar [--update UPDATE.pkg]\n       pkg-tools liberate GAME.pkg LICENSE.rap OUTPUT.pkg\n       pkg-tools gp4 create GAME_DIR OUTPUT.gp4 --passcode-file FILE --timestamp 'YYYY-MM-DD HH:MM:SS'\n       pkg-tools gp4 preflight PROJECT.gp4 --source-root GAME_DIR\n       pkg-tools gp4 image PROJECT.gp4 OUTPUT.pfs|OUTPUT.pfsc --source-root GAME_DIR\n       pkg-tools fpkg preflight INPUT.pkg";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn sfo_json(bytes: &[u8]) -> Result<Value, psf::Error> {
    let sfo = psf::parse(bytes)?;
    let entries: Vec<_> = sfo
        .entries
        .iter()
        .map(|e| {
            let (kind, value) = match e.value {
                psf::Value::Integer(n) => ("integer", json!(n)),
                psf::Value::Text(b) => ("text", json!(std::str::from_utf8(b).ok())),
                psf::Value::Binary(_) => ("binary", Value::Null),
                psf::Value::Unknown { .. } => ("unknown", Value::Null),
            };
            json!({"key": std::str::from_utf8(e.key).ok(), "key_hex": hex(e.key),
            "format": e.format, "kind": kind, "value": value,
            "raw_hex": hex(e.raw), "length": e.raw.len(), "max_length": e.max_len,
            "padding_hex": hex(e.padding)})
        })
        .collect();
    Ok(json!({"status": "available", "version": sfo.version, "entries": entries}))
}

fn inspect(file: File) -> Result<Value, Box<dyn Error>> {
    let mut reader = BufReader::new(file);
    let mut magic = [0; 4];
    reader
        .read_exact(&mut magic)
        .map_err(ps4_pkg::Error::from)?;
    reader.seek(SeekFrom::Start(0))?;
    if magic == *b"\0PSF" {
        let mut data = Vec::new();
        reader
            .take(psf::MAX_SIZE as u64 + 1)
            .read_to_end(&mut data)?;
        return Ok(json!({"format": "sfo", "sfo": sfo_json(&data)?}));
    }
    if magic == *b"\x7fPKG" {
        let mut pkg = ps3_pkg::Package::open(reader)?;
        let sfo = match pkg.read_param_sfo()? {
            Some(data) => sfo_json(&data)?,
            None => json!({"status": "missing"}),
        };
        let h = pkg.header();
        let content_id = h.content_id.split(|b| *b == 0).next().unwrap();
        let entries: Vec<_> = pkg.entries().iter().map(|e| json!({
            "path": e.path(), "offset": e.offset(), "size": e.size(), "flags": e.flags(),
            "kind": if e.kind() == ps3_pkg::FileKind::Directory { "directory" } else { "file" }
        })).collect();
        let metadata: Vec<_> = pkg
            .metadata()
            .iter()
            .map(|m| json!({"id": m.id, "raw_hex": hex(&m.data)}))
            .collect();
        return Ok(
            json!({"format": "ps3-pkg", "sfo": sfo, "authentication": "unverified",
            "header": {"release_type": h.release_type, "platform": h.platform,
                "content_id": std::str::from_utf8(content_id).ok(), "content_id_hex": hex(&h.content_id),
                "package_size": h.package_size, "entry_count": h.entry_count,
                "metadata_offset": h.metadata_offset, "metadata_count": h.metadata_count, "metadata_size": h.metadata_size,
                "data_offset": h.data_offset, "data_size": h.data_size,
                "qa_digest_hex": hex(&h.qa_digest), "nonce_hex": hex(&h.nonce)},
            "metadata": metadata, "entries": entries}),
        );
    }
    let mut pkg = ps4_pkg::Package::open(reader)?;
    let sfo = match pkg.read_param_sfo() {
        Ok(Some(data)) => sfo_json(&data)?,
        Ok(None) => json!({"status": "missing"}),
        Err(ps4_pkg::Error::DecryptionUnavailable {
            entry_id,
            key_index,
        }) => json!({
            "status": "decryption_unavailable", "entry_id": entry_id, "key_index": key_index
        }),
        Err(e) => return Err(e.into()),
    };
    let h = pkg.header();
    let content_id = h.content_id.split(|b| *b == 0).next().unwrap();
    let entries: Vec<_> = pkg.entries().iter().map(|e| json!({
        "id": e.id, "name_offset": e.name_offset, "flags1": e.flags1, "flags2": e.flags2,
        "offset": e.offset, "size": e.size, "encrypted": e.encrypted(), "key_index": e.key_index()
    })).collect();
    Ok(
        json!({"format": "ps4-pkg", "fpkg_status": "unverified", "sfo": sfo,
        "header": {"flags": h.flags, "content_id": std::str::from_utf8(content_id).ok(),
            "content_id_hex": hex(&h.content_id), "drm_type": h.drm_type,
            "content_type": h.content_type, "content_flags": h.content_flags,
            "entry_count": h.entry_count, "entry_table_offset": h.entry_table_offset,
            "body_offset": h.body_offset, "body_size": h.body_size,
            "pfs_flags": h.pfs_flags, "pfs_offset": h.pfs_offset, "pfs_size": h.pfs_size,
            "package_size": h.package_size}, "entries": entries}),
    )
}

fn human(out: &mut impl Write, doc: &Value) -> io::Result<()> {
    writeln!(out, "Format: {}", doc["format"].as_str().unwrap())?;
    if let Some(h) = doc.get("header") {
        if doc["format"] == "ps4-pkg" {
            writeln!(out, "FPKG: unverified (key recovery not performed)")?;
        }
        writeln!(out, "Content ID: {}", h["content_id"])?;
        writeln!(out, "Package size: {} bytes", h["package_size"])?;
        if doc["format"] == "ps4-pkg" {
            writeln!(
                out,
                "Content type: {:#x}; flags: {:#x}",
                h["content_type"].as_u64().unwrap(),
                h["content_flags"].as_u64().unwrap()
            )?;
        } else {
            writeln!(
                out,
                "Release: {}; signatures unverified",
                if h["release_type"] == 0x8000 {
                    "retail"
                } else {
                    "debug"
                }
            )?;
        }
        writeln!(out, "Package entries: {}", h["entry_count"])?;
    }
    let sfo = &doc["sfo"];
    writeln!(out, "SFO: {}", sfo["status"].as_str().unwrap())?;
    if sfo["status"] == "decryption_unavailable" {
        writeln!(
            out,
            "  Decryption material unavailable (key index {})",
            sfo["key_index"]
        )?;
    }
    if let Some(entries) = sfo["entries"].as_array() {
        for e in entries {
            let key = e["key"]
                .as_str()
                .map(|s| format!("{s:?}"))
                .unwrap_or_else(|| format!("hex:{}", e["key_hex"].as_str().unwrap()));
            let value = if e["value"].is_null() {
                format!("hex:{}", e["raw_hex"].as_str().unwrap())
            } else {
                e["value"].to_string()
            };
            writeln!(out, "  {key}: {value} ({})", e["kind"].as_str().unwrap())?;
        }
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    #[cfg(unix)]
    if args.len() == 6 && args[0] == "gp4" && args[1] == "image" && args[4] == "--source-root" {
        let cwd = env::current_dir()?;
        let mut xml = String::new();
        File::open(&args[2])?
            .take(ps4_pkg::gp4::MAX_XML_SIZE as u64 + 1)
            .read_to_string(&mut xml)?;
        let project = ps4_pkg::gp4::Project::parse(&xml, &cwd.join(&args[2]))?;
        let prepared =
            ps4_pkg::authoring::PreparedProject::new(&project, &cwd.join(&args[5]), || false)?;
        let containers = prepared
            .resources()
            .iter()
            .filter(|r| matches!(r.placement, ps4_pkg::authoring::Placement::Container(_)))
            .count();
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "Prepared GP4 sources: {} files, {} bytes; {} container resources excluded from inner image.",
            prepared.resources().len(),
            prepared.source_bytes(),
            containers
        )?;
        writeln!(
            out,
            "Scratch requirement: {} bytes (.pfs) / {} bytes (.pfsc), plus filesystem overhead. Sources will be revalidated before publication.",
            prepared.pfs_size(),
            prepared.pfsc_size()
        )?;
        out.flush()?;
        prepared.write_inner_new(&cwd.join(&args[3]), || false)?;
        writeln!(
            out,
            "Intermediate image published. Not a PKG; container resources, outer PFS, crypto, licenses and PlayGo are not emitted. Installation/launch unverified."
        )?;
        return Ok(());
    }
    if args.len() == 3 && args[0] == "fpkg" && args[1] == "preflight" {
        let package = ps4_pkg::Package::open(BufReader::new(File::open(&args[2])?))?;
        let inventory = ps4_pkg::authoring::preflight_package(package, || false)?;
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "Package authoring inventory: {} container records, {} application files; keystone size: {:?}.",
            inventory.records.len(),
            inventory.application_files,
            inventory.keystone_size
        )?;
        for record in &inventory.records {
            writeln!(
                out,
                "  Record {:#x}: {:?}, {} bytes, encrypted={}, key index={}",
                record.entry.id,
                record.role,
                record.entry.size,
                record.entry.encrypted(),
                record.entry.key_index()
            )?;
        }
        for blocker in &inventory.input_blockers {
            writeln!(out, "Input blocker: {blocker}")?;
        }
        for blocker in ps4_pkg::authoring::WRITER_BLOCKERS {
            writeln!(out, "Writer gate: {blocker}")?;
        }
        writeln!(
            out,
            "Inventory only; build unavailable. No PKG built or sources changed. Header/digest/NP bytes withheld; integrity and rebuild readiness are unverified."
        )?;
        return Ok(());
    }
    if args.len() == 5 && args[0] == "gp4" && args[1] == "preflight" && args[3] == "--source-root" {
        let cwd = env::current_dir()?;
        let mut xml = String::new();
        File::open(&args[2])?
            .take(ps4_pkg::gp4::MAX_XML_SIZE as u64 + 1)
            .read_to_string(&mut xml)?;
        let project = ps4_pkg::gp4::Project::parse(&xml, &cwd.join(&args[2]))?;
        let inventory = ps4_pkg::authoring::preflight(&project, &cwd.join(&args[4]), || false)?;
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "Authoring inventory: {} (APP_VER {}, VERSION {}); {} files, {} directories, {} source bytes.",
            inventory.identity.title_id,
            inventory.identity.app_version,
            inventory.identity.version,
            inventory.resources.len(),
            inventory.directory_count,
            inventory.source_bytes
        )?;
        for resource in &inventory.resources {
            writeln!(
                out,
                "  {:?}: {:?}, {} bytes; source {:?} (absolute={}, outside-project={})",
                resource.source.target,
                resource.kind,
                resource.size,
                resource.source.resolved,
                resource.source.absolute_reference,
                resource.source.outside_project_directory
            )?;
        }
        for blocker in &inventory.input_blockers {
            writeln!(out, "Input blocker: {blocker}")?;
        }
        for blocker in ps4_pkg::authoring::WRITER_BLOCKERS {
            writeln!(out, "Writer gate: {blocker}")?;
        }
        writeln!(
            out,
            "Inventory only; build unavailable. No PKG built or sources changed."
        )?;
        return Ok(());
    }
    if args.len() == 8
        && args[0] == "gp4"
        && args[1] == "create"
        && args[4] == "--passcode-file"
        && args[6] == "--timestamp"
    {
        use std::path::Path;
        let cwd = env::current_dir()?;
        let source = cwd.join(&args[2]);
        let passcode_file = cwd.join(&args[5]);
        if std::fs::canonicalize(&passcode_file)?.starts_with(std::fs::canonicalize(&source)?) {
            return Err("passcode file must be outside the application tree".into());
        }
        let mut passcode = String::new();
        File::open(passcode_file)?
            .take(34)
            .read_to_string(&mut passcode)?;
        if passcode.ends_with('\n') {
            passcode.pop();
        }
        let settings = ps4_pkg::gp4::Settings {
            passcode,
            timestamp: args[7].to_str().ok_or("timestamp must be UTF-8")?.into(),
            creation_date: None,
            volume_id: None,
            chunk_label: "Chunk #0".into(),
            scenario_label: "Scenario #0".into(),
        };
        let project = ps4_pkg::gp4::Project::from_directory(
            &source,
            &cwd.join(Path::new(&args[3])),
            settings,
        )?;
        let preflight = project.preflight(&source)?;
        let external = preflight
            .sources
            .iter()
            .filter(|s| s.absolute_reference || s.outside_project_directory)
            .count();
        project.write_new(&source)?;
        writeln!(
            io::stdout().lock(),
            "Created base GP4: {} (APP_VER {}, VERSION {}); {} files, {} external/absolute references. Approved source root: {}. No PKG built.",
            preflight.identity.title_id,
            preflight.identity.app_version,
            preflight.identity.version,
            project.files().len(),
            external,
            source.display()
        )?;
        return Ok(());
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        writeln!(io::stdout().lock(), "{USAGE}")?;
        return Ok(());
    }
    if (args.len() == 2 || (args.len() == 3 && args[2] == "--json")) && args[0] == "trophies" {
        let sets = pkg_ops::trophies::read(std::path::Path::new(&args[1]))?;
        let mut out = io::stdout().lock();
        if args.len() == 3 {
            let sets: Vec<_> = sets
                .iter()
                .map(|set| {
                    json!({
                        "path": set.path, "title": set.title, "error": set.error,
                        "trophies": set.trophies.iter().map(|t| json!({
                            "id": t.id, "name": t.name, "description": t.description,
                            "grade": t.grade, "hidden": t.hidden, "group": t.group,
                        })).collect::<Vec<_>>()
                    })
                })
                .collect();
            serde_json::to_writer_pretty(&mut out, &json!({"sets": sets}))?;
            writeln!(out)?;
        } else {
            if sets.is_empty() {
                writeln!(out, "No trophy sets found.")?;
            }
            for set in &sets {
                writeln!(out, "{} ({})", set.title, set.path)?;
                if let Some(error) = &set.error {
                    writeln!(out, "  Unavailable: {error}")?;
                }
                for t in &set.trophies {
                    writeln!(
                        out,
                        "  {:03} {}{} — {} [group {}]\n      {}",
                        t.id,
                        t.grade,
                        if t.hidden { " · Hidden" } else { "" },
                        t.name,
                        t.group,
                        t.description
                    )?;
                }
            }
        }
        if sets.iter().any(|set| set.error.is_some()) {
            return Err("one or more trophy sets could not be read".into());
        }
        return Ok(());
    }
    if args.len() == 4 && args[0] == "liberate" {
        pkg_ops::liberate::liberate(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
            std::path::Path::new(&args[3]),
            false,
            &AtomicBool::new(false),
            |_, _| {},
        )?;
        eprintln!(
            "RAP-less package saved: {}",
            std::path::Path::new(&args[3]).display()
        );
        return Ok(());
    }
    if (args.len() == 3 || (args.len() == 5 && args[3] == "--update")) && args[0] == "convert" {
        return convert::run(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
            args.get(4).map(std::path::Path::new),
        );
    }
    if args.len() == 3 && args[0] == "pack" {
        zarchive::pack_directory(&args[1], &args[2])?;
        eprintln!(
            "Archive complete: {}",
            std::path::Path::new(&args[2]).display()
        );
        return Ok(());
    }
    if args.len() == 3 && args[0] == "extract" {
        eprintln!("Extracting application entries...");
        pkg_ops::extract(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
            &AtomicBool::new(false),
            |_, _| {},
        )?;
        eprintln!(
            "Extraction complete: {}",
            std::path::Path::new(&args[2]).display()
        );
        return Ok(());
    }
    if !(args.len() == 2 || args.len() == 3)
        || args[0] != "inspect"
        || (args.len() == 3 && args[2] != "--json")
    {
        return Err(USAGE.into());
    }
    let doc = inspect(File::open(&args[1])?)?;
    let mut out = io::stdout().lock();
    if args.len() == 3 {
        serde_json::to_writer_pretty(&mut out, &doc)?;
        writeln!(out)?;
    } else {
        human(&mut out, &doc)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pkg-tools: {e}");
            ExitCode::FAILURE
        }
    }
}
