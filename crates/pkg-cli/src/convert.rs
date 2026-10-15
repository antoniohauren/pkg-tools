use std::{
    error::Error,
    fs::File,
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Package = ps4_pkg::Package<BufReader<File>>;
type Game = ps4_pkg::Game<BufReader<File>>;

#[derive(Debug)]
struct Identity {
    category: String,
    title: String,
    content: String,
}

fn text(sfo: &psf::Sfo<'_>, key: &[u8]) -> Result<String> {
    match sfo.get(key).map(|e| &e.value) {
        Some(psf::Value::Text(bytes)) if !bytes.is_empty() && bytes.is_ascii() => {
            Ok(std::str::from_utf8(bytes)?.to_owned())
        }
        _ => Err(format!("missing or invalid SFO {}", String::from_utf8_lossy(key)).into()),
    }
}

fn open(path: &Path) -> Result<(Package, Identity)> {
    let mut package = Package::open(BufReader::new(File::open(path)?))?;
    let bytes = package
        .read_param_sfo()?
        .ok_or("conversion requires PARAM.SFO")?;
    let sfo = psf::parse(&bytes)?;
    let identity = Identity {
        category: text(&sfo, b"CATEGORY")?,
        title: text(&sfo, b"TITLE_ID")?,
        content: text(&sfo, b"CONTENT_ID")?,
    };
    let header_id = package
        .header()
        .content_id
        .split(|b| *b == 0)
        .next()
        .unwrap();
    if header_id != identity.content.as_bytes() {
        return Err("PKG header and SFO content IDs differ".into());
    }
    Ok((package, identity))
}

fn validate(base: &Identity, update: Option<&Identity>) -> Result<()> {
    if base.category != "gd" {
        return Err("base input must be a GD game (SFO CATEGORY=gd)".into());
    }
    if base.title.len() != 9
        || !base.title.starts_with("CUSA")
        || !base.title.as_bytes()[4..].iter().all(u8::is_ascii_digit)
        || base.content.get(7..16) != Some(base.title.as_str())
    {
        return Err("invalid base title/content ID relationship".into());
    }
    if let Some(update) = update {
        if update.category != "gp" {
            return Err("--update input must be an update (SFO CATEGORY=gp)".into());
        }
        if update.title != base.title || update.content != base.content {
            return Err("base and update title/content IDs do not match".into());
        }
    }
    Ok(())
}

fn update_path(output: &Path) -> Result<PathBuf> {
    if output.extension().is_none_or(|e| e != "zar") {
        return Err("conversion output must have lowercase .zar extension".into());
    }
    let stem = output.file_stem().ok_or("output filename missing")?;
    let mut name = stem.to_os_string();
    name.push("-UPDATE.zar");
    Ok(output.with_file_name(name))
}

fn check_paths(game: &Game) -> Result<()> {
    for entry in game.entries() {
        if entry.path().split('/').any(|name| name.len() > 127) {
            return Err(format!(
                "ZArchive reader requires components <=127 bytes: {}",
                entry.path()
            )
            .into());
        }
    }
    Ok(())
}

struct ProgressReader<'a, R, C, P> {
    inner: R,
    cancelled: &'a C,
    progress: &'a mut P,
    written: &'a mut u64,
    total: u64,
}

fn check_cancel(cancelled: &impl Fn() -> bool) -> io::Result<()> {
    if cancelled() {
        Err(io::Error::other(
            "Conversion cancelled; unpublished archives were removed.",
        ))
    } else {
        Ok(())
    }
}

impl<R: Read, C: Fn() -> bool, P: FnMut(u64, u64)> Read for ProgressReader<'_, R, C, P> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        check_cancel(self.cancelled)?;
        let count = self.inner.read(buf)?;
        *self.written += count as u64;
        (self.progress)(*self.written, self.total);
        Ok(count)
    }
}

fn stream(
    mut game: Game,
    mut writer: zarchive::Writer,
    cancelled: &impl Fn() -> bool,
    progress: &mut impl FnMut(u64, u64),
    written: &mut u64,
    total: u64,
) -> Result<zarchive::Writer> {
    let count = game.entries().len();
    for index in 0..count {
        check_cancel(cancelled)?;
        let entry = &game.entries()[index];
        let path = entry.path().to_owned();
        let size = entry.size();
        match entry.kind() {
            ps4_pkg::FileKind::Directory => writer.add_directory(&path)?,
            ps4_pkg::FileKind::File => {
                writer.add_file(
                    &path,
                    size,
                    ProgressReader {
                        inner: game.read_entry(index)?,
                        cancelled,
                        progress,
                        written,
                        total,
                    },
                )?;
            }
        }
    }
    Ok(writer)
}

pub fn run(base: &Path, output: &Path, update: Option<&Path>) -> Result<()> {
    let mut last = 0;
    run_with_progress(
        base,
        output,
        update,
        || false,
        |written, total| {
            if written - last >= 64 * 1024 * 1024 || written == total {
                eprintln!("Archived {written}/{total} bytes");
                last = written;
            }
        },
    )?;
    eprintln!("Archive complete: {}", output.display());
    if update.is_some() {
        eprintln!("Archive complete: {}", update_path(output)?.display());
    }
    Ok(())
}

/// Streams decoded bytes, with cooperative cancellation before publication.
/// Preparation and final publication are not interruptible. Paired publication
/// is not atomic; errors identify a base archive already published.
pub fn run_with_progress(
    base: &Path,
    output: &Path,
    update: Option<&Path>,
    cancelled: impl Fn() -> bool,
    mut progress: impl FnMut(u64, u64),
) -> Result<()> {
    check_cancel(&cancelled)?;
    let update_output = update_path(output)?;
    let (base, identity) = open(base)?;
    let update = update.map(open).transpose()?;
    validate(&identity, update.as_ref().map(|(_, id)| id))?;
    let base = base.open_game()?;
    let update = update.map(|(pkg, _)| pkg.open_game()).transpose()?;
    check_paths(&base)?;
    if let Some(game) = &update {
        check_paths(game)?;
    }
    // Reserve both scratch writers before streaming; existing outputs fail early.
    let base_writer = zarchive::Writer::create(output)?;
    let update_writer = update
        .as_ref()
        .map(|_| zarchive::Writer::create(&update_output))
        .transpose()?;
    let total = std::iter::once(&base)
        .chain(update.iter())
        .flat_map(|game| game.entries())
        .filter(|entry| entry.kind() == ps4_pkg::FileKind::File)
        .try_fold(0u64, |sum, entry| sum.checked_add(entry.size()))
        .ok_or("conversion size overflow")?;
    let mut written = 0;
    progress(0, total);
    let base_writer = stream(
        base,
        base_writer,
        &cancelled,
        &mut progress,
        &mut written,
        total,
    )?;
    let update_writer = match (update, update_writer) {
        (Some(game), Some(writer)) => Some(stream(
            game,
            writer,
            &cancelled,
            &mut progress,
            &mut written,
            total,
        )?),
        _ => None,
    };
    check_cancel(&cancelled)?;
    base_writer.finish()?;
    if let Some(writer) = update_writer {
        writer.finish().map_err(|e| {
            format!(
                "base archive is complete at {}; update publication failed: {e}",
                output.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_progress_and_cancellation() {
        let cancelled = std::cell::Cell::new(false);
        let mut written = 0;
        let mut samples = Vec::new();
        let check = || cancelled.get();
        let mut progress = |written, total| samples.push((written, total));
        let mut reader = ProgressReader {
            inner: io::Cursor::new(b"abcdef"),
            cancelled: &check,
            progress: &mut progress,
            written: &mut written,
            total: 6,
        };
        let mut buf = [0; 3];
        assert_eq!(reader.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"abc");
        cancelled.set(true);
        assert_eq!(
            reader.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        cancelled.set(false);
        assert_eq!(reader.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"def");
        assert_eq!(written, 6);
        assert_eq!(samples, [(3, 6), (6, 6)]);
        assert!(
            run_with_progress(
                Path::new("missing.pkg"),
                Path::new("unused.zar"),
                None,
                || true,
                |_, _| {}
            )
            .unwrap_err()
            .to_string()
            .contains("cancelled")
        );
    }
    fn identity(category: &str) -> Identity {
        Identity {
            category: category.into(),
            title: "CUSA12345".into(),
            content: "UP0000-CUSA12345_00-ABCDEFGHIJKLMNOP".into(),
        }
    }
    #[test]
    fn pairing_and_sibling_names() {
        let base = identity("gd");
        let mut update = identity("gp");
        assert!(validate(&base, None).is_ok());
        assert!(validate(&base, Some(&update)).is_ok());
        assert!(validate(&update, None).is_err());
        assert!(validate(&base, Some(&base)).is_err());
        update.title = "CUSA54321".into();
        assert!(validate(&base, Some(&update)).is_err());
        update = identity("gp");
        update.content.push('X');
        assert!(validate(&base, Some(&update)).is_err());
        assert_eq!(
            update_path(Path::new("games/My Game.zar")).unwrap(),
            Path::new("games/My Game-UPDATE.zar")
        );
        assert!(update_path(Path::new("Game.ZAR")).is_err());
    }
}
