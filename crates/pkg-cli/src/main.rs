use pkg_cli::convert;

use serde_json::{Value, json};
use std::{
    env,
    error::Error,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    process::ExitCode,
};

const USAGE: &str = "Usage: pkg-tools inspect INPUT.pkg [--json]\n       pkg-tools inspect PARAM.SFO [--json]\n       pkg-tools extract INPUT.pkg OUTPUT_DIR\n       pkg-tools pack INPUT_DIR OUTPUT.zar\n       pkg-tools convert GAME.pkg OUTPUT.zar [--update UPDATE.pkg]\n       pkg-tools liberate GAME.pkg LICENSE.rap OUTPUT.pkg";

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
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        writeln!(io::stdout().lock(), "{USAGE}")?;
        return Ok(());
    }
    if args.len() == 4 && args[0] == "liberate" {
        let mut bytes = Vec::new();
        File::open(&args[2])?.take(17).read_to_end(&mut bytes)?;
        let rap = ps3_pkg::Rap::from_bytes(&bytes)?;
        let mut package = ps3_pkg::Package::open(BufReader::new(File::open(&args[1])?))?;
        package.liberate_with_progress(&rap, &args[3], || false, |_, _| {})?;
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
        let mut reader = BufReader::new(File::open(&args[1])?);
        let mut magic = [0; 4];
        reader.read_exact(&mut magic)?;
        reader.rewind()?;
        if magic == *b"\x7fPKG" {
            let mut pkg = ps3_pkg::Package::open(reader)?;
            eprintln!("Extracting {} application entries...", pkg.entries().len());
            pkg.extract(&args[2])?;
        } else {
            let mut game = ps4_pkg::Package::open(reader)?.open_game()?;
            eprintln!("Extracting {} application entries...", game.entries().len());
            game.extract(&args[2])?;
        }
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
