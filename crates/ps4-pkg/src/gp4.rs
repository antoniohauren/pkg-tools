//! Bounded standalone-app GP4 interchange, not a package builder.
//!
//! Source paths resolve against an absolute project location. Import does not
//! approve sources: call `preflight` with an explicitly approved source root.
//! Sources must remain stable during preflight/export; this is not a sandbox
//! against concurrent filesystem mutation. Passcodes are intentionally not Debug.

use roxmltree::{Document, Node, ParsingOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub const MAX_XML_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_NODES: u32 = 100_000;
pub const MAX_DEPTH: usize = 64;
pub const MAX_PATH_SIZE: usize = 4096;
const MAX_ITEMS: usize = 32_768;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// All times are explicit UTC, without a suffix: `YYYY-MM-DD HH:MM:SS`.
/// `creation_date` may instead be `YYYY-MM-DD`; dynamic dates are unsupported.
pub struct Settings {
    pub passcode: String,
    pub timestamp: String,
    pub creation_date: Option<String>,
    pub volume_id: Option<String>,
    pub chunk_label: String,
    pub scenario_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub target: String,
    pub source: String,
}

pub struct Project {
    location: PathBuf,
    content_id: String,
    settings: Settings,
    files: Vec<Mapping>,
    directories: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Identity {
    pub content_id: String,
    pub title_id: String,
    pub app_version: String,
    pub version: String,
}

#[derive(Debug)]
pub struct SourceReference {
    pub target: String,
    pub resolved: PathBuf,
    pub absolute_reference: bool,
    pub outside_project_directory: bool,
}

#[derive(Debug)]
pub struct Preflight {
    pub identity: Identity,
    /// Includes every source, explicitly identifying absolute/external references.
    pub sources: Vec<SourceReference>,
}

fn shape(node: Node<'_, '_>, attributes: &[&str], children: &[&str]) -> io::Result<()> {
    if node.tag_name().namespace().is_some() {
        return Err(invalid(format!(
            "unsupported namespaced element {}",
            node.tag_name().name()
        )));
    }
    for attr in node.attributes() {
        if attr.namespace().is_some() || !attributes.contains(&attr.name()) {
            return Err(invalid(format!(
                "unsupported {} attribute {}",
                node.tag_name().name(),
                attr.name()
            )));
        }
    }
    for child in node.children() {
        if child.is_element() && !children.contains(&child.tag_name().name()) {
            return Err(invalid(format!(
                "unsupported element {}",
                child.tag_name().name()
            )));
        }
        if child.is_pi()
            || (child.is_text()
                && !child.text().unwrap_or("").trim().is_empty()
                && children != ["#text"])
        {
            return Err(invalid(format!(
                "unexpected content in {}",
                node.tag_name().name()
            )));
        }
    }
    Ok(())
}

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> io::Result<Node<'a, 'input>> {
    let mut found = node.children().filter(|n| n.has_tag_name(name));
    let value = found
        .next()
        .ok_or_else(|| invalid(format!("missing element {name}")))?;
    if found.next().is_some() {
        return Err(invalid(format!("duplicate element {name}")));
    }
    Ok(value)
}

fn attr<'a>(node: Node<'a, '_>, name: &str) -> io::Result<&'a str> {
    node.attribute(name).ok_or_else(|| {
        invalid(format!(
            "missing {} attribute {name}",
            node.tag_name().name()
        ))
    })
}

fn exact_attr(node: Node<'_, '_>, name: &str, expected: &str) -> io::Result<()> {
    if attr(node, name)? != expected {
        return Err(invalid(format!(
            "unsupported {} attribute {name}",
            node.tag_name().name()
        )));
    }
    Ok(())
}

fn text(node: Node<'_, '_>) -> io::Result<String> {
    shape(node, &[], &["#text"])?;
    Ok(node
        .children()
        .filter(Node::is_text)
        .filter_map(|n| n.text())
        .collect())
}

fn valid_date(value: &str, date_only: bool) -> bool {
    let b = value.as_bytes();
    if !(b.len() == 19 || (date_only && b.len() == 10)) {
        return false;
    }
    if b[4] != b'-'
        || b[7] != b'-'
        || (b.len() == 19 && (b[10] != b' ' || b[13] != b':' || b[16] != b':'))
    {
        return false;
    }
    if !b
        .iter()
        .enumerate()
        .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16) || c.is_ascii_digit())
    {
        return false;
    }
    let number = |start, end| {
        b[start..end]
            .iter()
            .fold(0u32, |n, c| n * 10 + u32::from(c - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    year != 0
        && (1..=days).contains(&number(8, 10))
        && (b.len() == 10 || (number(11, 13) < 24 && number(14, 16) < 60 && number(17, 19) < 60))
}

pub(crate) fn valid_content_id(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b[6] == b'-'
        && b[16] == b'_'
        && b[19] == b'-'
        && b[..2].iter().all(u8::is_ascii_uppercase)
        && b[2..6].iter().all(u8::is_ascii_digit)
        && &b[7..11] == b"CUSA"
        && b[11..16].iter().all(u8::is_ascii_digit)
        && b[17..19].iter().all(u8::is_ascii_digit)
        && b[20..]
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn valid_string(s: &str) -> bool {
    s.len() <= MAX_PATH_SIZE
        && s.chars().all(|c| {
            matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')
        })
}

fn target(path: &str) -> io::Result<()> {
    if path.len() > MAX_PATH_SIZE
        || path.split('/').count() > MAX_DEPTH - 4
        || !path.split('/').all(pkg_fs::valid_component)
    {
        return Err(invalid(format!("unsafe target path {path:?}")));
    }
    Ok(())
}

pub(crate) fn absolute(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid("project/source policy location must be absolute"));
    }
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir | Component::Normal(_) => result.push(part),
            Component::CurDir => (),
            Component::ParentDir if result.parent().is_some() => {
                result.pop();
            }
            _ => return Err(invalid("path escapes filesystem root")),
        }
    }
    Ok(result)
}

pub(crate) fn no_symlinks(path: &Path) -> io::Result<()> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part);
        if fs::symlink_metadata(&prefix)?.file_type().is_symlink() {
            return Err(invalid("symlink source/project parent is unsupported"));
        }
    }
    Ok(())
}

impl Project {
    /// Parse only the supported schema; filesystem approval is separate.
    /// `location` is the absolute intended GP4 filename, not its directory.
    pub fn parse(xml: &str, location: &Path) -> io::Result<Self> {
        if xml.len() > MAX_XML_SIZE {
            return Err(invalid("GP4 XML exceeds 8 MiB"));
        }
        let doc = Document::parse_with_options(
            xml,
            ParsingOptions {
                allow_dtd: false,
                nodes_limit: MAX_NODES,
                ..ParsingOptions::default()
            },
        )
        .map_err(|_| invalid("malformed GP4 XML or XML resource limit exceeded (DTD forbidden)"))?;
        if doc.descendants().any(|n| n.ancestors().count() > MAX_DEPTH) {
            return Err(invalid("GP4 XML depth exceeds 64"));
        }
        let root = doc.root_element();
        if !root.has_tag_name("psproject") {
            return Err(invalid("expected psproject"));
        }
        shape(root, &["fmt", "version"], &["volume", "files", "rootdir"])?;
        exact_attr(root, "fmt", "gp4")?;
        exact_attr(root, "version", "1000")?;
        let volume = child(root, "volume")?;
        shape(
            volume,
            &[],
            &[
                "volume_type",
                "volume_id",
                "volume_ts",
                "package",
                "chunk_info",
            ],
        )?;
        if text(child(volume, "volume_type")?)? != "pkg_ps4_app" {
            return Err(invalid(
                "unsupported volume_type (only pkg_ps4_app; updates/remaster/delta blocked)",
            ));
        }
        let volume_id = if volume.children().any(|n| n.has_tag_name("volume_id")) {
            Some(text(child(volume, "volume_id")?)?)
        } else {
            None
        };
        let package = child(volume, "package")?;
        shape(
            package,
            &[
                "content_id",
                "passcode",
                "storage_type",
                "app_type",
                "c_date",
            ],
            &[],
        )?;
        exact_attr(package, "storage_type", "digital50")?;
        exact_attr(package, "app_type", "full")?;
        let chunks = child(volume, "chunk_info")?;
        shape(
            chunks,
            &["chunk_count", "scenario_count"],
            &["chunks", "scenarios"],
        )?;
        exact_attr(chunks, "chunk_count", "1")?;
        exact_attr(chunks, "scenario_count", "1")?;
        let list = child(chunks, "chunks")?;
        shape(list, &[], &["chunk"])?;
        let chunk = child(list, "chunk")?;
        shape(chunk, &["id", "layer_no", "label"], &[])?;
        exact_attr(chunk, "id", "0")?;
        exact_attr(chunk, "layer_no", "0")?;
        let scenarios = child(chunks, "scenarios")?;
        shape(scenarios, &["default_id"], &["scenario"])?;
        exact_attr(scenarios, "default_id", "0")?;
        let scenario = child(scenarios, "scenario")?;
        shape(
            scenario,
            &["id", "type", "initial_chunk_count", "label"],
            &["#text"],
        )?;
        exact_attr(scenario, "id", "0")?;
        exact_attr(scenario, "type", "sp")?;
        exact_attr(scenario, "initial_chunk_count", "1")?;
        if scenario
            .children()
            .filter(Node::is_text)
            .filter_map(|n| n.text())
            .collect::<String>()
            != "0"
        {
            return Err(invalid("unsupported scenario chunk list"));
        }
        let files_node = child(root, "files")?;
        shape(files_node, &["img_no"], &["file"])?;
        exact_attr(files_node, "img_no", "0")?;
        let mut files = Vec::new();
        for file in files_node.children().filter(Node::is_element) {
            shape(file, &["targ_path", "orig_path"], &[])?;
            files.push(Mapping {
                target: attr(file, "targ_path")?.into(),
                source: attr(file, "orig_path")?.into(),
            });
        }
        let rootdir = child(root, "rootdir")?;
        shape(rootdir, &[], &["dir"])?;
        let mut directories = BTreeSet::new();
        fn dirs(node: Node<'_, '_>, parent: &str, out: &mut BTreeSet<String>) -> io::Result<()> {
            for dir in node.children().filter(Node::is_element) {
                shape(dir, &["targ_name"], &["dir"])?;
                let name = attr(dir, "targ_name")?;
                if !pkg_fs::valid_component(name) {
                    return Err(invalid("unsafe dir targ_name"));
                }
                let path = if parent.is_empty() {
                    name.into()
                } else {
                    format!("{parent}/{name}")
                };
                target(&path)?;
                if out.len() >= MAX_ITEMS {
                    return Err(invalid("GP4 exceeds 32768 files/directories"));
                }
                if !out.insert(path.clone()) {
                    return Err(invalid("duplicate directory"));
                }
                dirs(dir, &path, out)?;
            }
            Ok(())
        }
        dirs(rootdir, "", &mut directories)?;
        let project = Self {
            location: absolute(location)?,
            content_id: attr(package, "content_id")?.into(),
            files,
            directories,
            settings: Settings {
                passcode: attr(package, "passcode")?.into(),
                timestamp: text(child(volume, "volume_ts")?)?,
                creation_date: package.attribute("c_date").map(str::to_owned),
                volume_id,
                chunk_label: attr(chunk, "label")?.into(),
                scenario_label: attr(scenario, "label")?.into(),
            },
        };
        project.validate()?;
        Ok(project)
    }

    pub fn files(&self) -> &[Mapping] {
        &self.files
    }
    pub fn directories(&self) -> &BTreeSet<String> {
        &self.directories
    }
    pub fn content_id(&self) -> &str {
        &self.content_id
    }
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if !valid_content_id(&self.content_id) {
            return Err(invalid("invalid content_id"));
        }
        if self.settings.passcode.len() != 32
            || !self
                .settings
                .passcode
                .bytes()
                .all(|b| (32..=126).contains(&b))
        {
            return Err(invalid(
                "passcode must contain exactly 32 printable ASCII bytes",
            ));
        }
        if !valid_date(&self.settings.timestamp, false)
            || self
                .settings
                .creation_date
                .as_ref()
                .is_some_and(|d| !valid_date(d, true))
        {
            return Err(invalid(
                "invalid explicit UTC volume_ts/c_date; actual_datetime unsupported",
            ));
        }
        if [&self.settings.chunk_label, &self.settings.scenario_label]
            .into_iter()
            .chain(self.settings.volume_id.iter())
            .any(|s| !valid_string(s))
        {
            return Err(invalid("invalid label/volume_id"));
        }
        if self.files.len() + self.directories.len() > MAX_ITEMS {
            return Err(invalid("GP4 exceeds 32768 files/directories"));
        }
        let mut seen = BTreeMap::new();
        for path in self
            .directories
            .iter()
            .chain(self.files.iter().map(|f| &f.target))
        {
            target(path)?;
            if seen.insert(path.to_ascii_lowercase(), path).is_some() {
                return Err(invalid("duplicate/case/file-directory target collision"));
            }
            if let Some((parent, _)) = path.rsplit_once('/')
                && !self.directories.contains(parent)
            {
                return Err(invalid("missing exact target parent directory"));
            }
        }
        for file in &self.files {
            if file.source.is_empty()
                || !valid_string(&file.source)
                || file
                    .source
                    .contains(['\\', '\0', '\n', '\r', '\t', '*', '?', ':'])
            {
                return Err(invalid("invalid orig_path (forward-slash paths required)"));
            }
        }
        if !self.files.iter().any(|f| f.target == "eboot.bin")
            || !self.files.iter().any(|f| f.target == "sce_sys/param.sfo")
        {
            return Err(invalid(
                "base project requires eboot.bin and sce_sys/param.sfo",
            ));
        }
        Ok(())
    }

    pub(crate) fn check_source_traversal(&self) -> io::Result<()> {
        let parent = self
            .location
            .parent()
            .ok_or_else(|| invalid("project has no parent"))?;
        for mapping in &self.files {
            no_symlinks(&parent.join(&mapping.source))?;
        }
        Ok(())
    }

    /// Inventory source references without reading their contents or approving them.
    pub fn source_references(&self) -> io::Result<Vec<SourceReference>> {
        let parent = self
            .location
            .parent()
            .ok_or_else(|| invalid("project has no parent"))?;
        self.files
            .iter()
            .map(|f| {
                Ok(SourceReference {
                    target: f.target.clone(),
                    resolved: absolute(&parent.join(&f.source))?,
                    absolute_reference: Path::new(&f.source).is_absolute(),
                    outside_project_directory: !absolute(&parent.join(&f.source))?
                        .starts_with(parent),
                })
            })
            .collect()
    }

    /// Explicitly approve one absolute source root (including external references
    /// beneath it). Reject symlinks in any component, special files and mismatched
    /// SFO identity. No source data or SFO metadata is changed.
    pub fn preflight(&self, approved_root: &Path) -> io::Result<Preflight> {
        self.validate()?;
        no_symlinks(approved_root)?;
        let root = absolute(approved_root)?;
        no_symlinks(&root)?;
        if !root.is_dir() {
            return Err(invalid("approved source root is not a directory"));
        }
        let sources = self.source_references()?;
        let mut identity = None;
        for (source, mapping) in sources.iter().zip(&self.files) {
            if !source.resolved.starts_with(&root) {
                return Err(invalid("source outside explicitly approved root"));
            }
            // Check original traversal as well: `link/../file` must not hide a symlink.
            no_symlinks(
                &self
                    .location
                    .parent()
                    .ok_or_else(|| invalid("project has no parent"))?
                    .join(&mapping.source),
            )?;
            if !fs::symlink_metadata(&source.resolved)?.is_file() {
                return Err(invalid("source must be a regular file"));
            }
            if source.target == "sce_sys/param.sfo" {
                let mut bytes = Vec::new();
                File::open(&source.resolved)?
                    .take(psf::MAX_SIZE as u64 + 1)
                    .read_to_end(&mut bytes)?;
                let found = sfo_identity(&bytes)?;
                if found.content_id != self.content_id {
                    return Err(invalid("GP4 content_id disagrees with SFO"));
                }
                identity = Some(found);
            }
        }
        Ok(Preflight {
            identity: identity.ok_or_else(|| invalid("missing SFO"))?,
            sources,
        })
    }

    /// Generate mappings, including empty directories, from a stable source tree.
    /// Sources are relative to `location`, never to the process working directory.
    pub fn from_directory(source: &Path, location: &Path, settings: Settings) -> io::Result<Self> {
        no_symlinks(source)?;
        let source = absolute(source)?;
        no_symlinks(&source)?;
        if !source.is_dir() {
            return Err(invalid("source must be a directory"));
        }
        let location = absolute(location)?;
        if location.starts_with(&source) {
            return Err(invalid("project output must be outside source tree"));
        }
        let parent = location
            .parent()
            .ok_or_else(|| invalid("project has no parent"))?;
        let mut files = Vec::new();
        let mut directories = BTreeSet::new();
        let mut pending = vec![String::new()];
        while let Some(relative) = pending.pop() {
            for entry in fs::read_dir(source.join(&relative))? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid("non-UTF-8 source filename"))?;
                let path = if relative.is_empty() {
                    name
                } else {
                    format!("{relative}/{name}")
                };
                target(&path)?;
                if files.len() + directories.len() >= MAX_ITEMS {
                    return Err(invalid("GP4 exceeds 32768 files/directories"));
                }
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    directories.insert(path.clone());
                    pending.push(path);
                } else if kind.is_file() {
                    files.push(Mapping {
                        source: relative_path(parent, &source.join(&path))?,
                        target: path,
                    });
                } else {
                    return Err(invalid("symlinks and special source files unsupported"));
                }
            }
        }
        files.sort_by(|a, b| a.target.cmp(&b.target));
        let mut bytes = Vec::new();
        File::open(source.join("sce_sys/param.sfo"))?
            .take(psf::MAX_SIZE as u64 + 1)
            .read_to_end(&mut bytes)?;
        let identity = sfo_identity(&bytes)?;
        let project = Self {
            location,
            content_id: identity.content_id,
            settings,
            files,
            directories,
        };
        project.preflight(&source)?;
        Ok(project)
    }

    /// Serialize the supported settings/mappings. XML bytes contain the passcode;
    /// do not log them. Does not assert filesystem or package-build compatibility.
    pub fn to_xml(&self) -> io::Result<String> {
        self.validate()?;
        let s = &self.settings;
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<psproject fmt=\"gp4\" version=\"1000\"><volume><volume_type>pkg_ps4_app</volume_type>",
        );
        if let Some(id) = &s.volume_id {
            out.push_str(&format!("<volume_id>{}</volume_id>", escape(id)));
        }
        out.push_str(&format!("<volume_ts>{}</volume_ts><package content_id=\"{}\" passcode=\"{}\" storage_type=\"digital50\" app_type=\"full\"", escape(&s.timestamp), escape(&self.content_id), escape(&s.passcode)));
        if let Some(date) = &s.creation_date {
            out.push_str(&format!(" c_date=\"{}\"", escape(date)));
        }
        out.push_str(&format!("/><chunk_info chunk_count=\"1\" scenario_count=\"1\"><chunks><chunk id=\"0\" layer_no=\"0\" label=\"{}\"/></chunks><scenarios default_id=\"0\"><scenario id=\"0\" type=\"sp\" initial_chunk_count=\"1\" label=\"{}\">0</scenario></scenarios></chunk_info></volume><files img_no=\"0\">", escape(&s.chunk_label), escape(&s.scenario_label)));
        for file in &self.files {
            out.push_str(&format!(
                "<file targ_path=\"{}\" orig_path=\"{}\"/>",
                escape(&file.target),
                escape(&file.source)
            ));
            if out.len() > MAX_XML_SIZE {
                return Err(invalid("GP4 XML exceeds 8 MiB"));
            }
        }
        out.push_str("</files><rootdir>");
        let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for path in &self.directories {
            children
                .entry(path.rsplit_once('/').map_or("", |(p, _)| p))
                .or_default()
                .push(path);
        }
        fn dirs(out: &mut String, parent: &str, all: &BTreeMap<&str, Vec<&str>>) -> io::Result<()> {
            for path in all.get(parent).into_iter().flatten() {
                let name = path.rsplit('/').next().unwrap_or(path);
                out.push_str(&format!("<dir targ_name=\"{}\">", escape(name)));
                if out.len() > MAX_XML_SIZE {
                    return Err(invalid("GP4 XML exceeds 8 MiB"));
                }
                dirs(out, path, all)?;
                out.push_str("</dir>");
            }
            Ok(())
        }
        dirs(&mut out, "", &children)?;
        out.push_str("</rootdir></psproject>\n");
        // Enforce the same byte/node/depth bounds for exports and imports.
        Self::parse(&out, &self.location)?;
        Ok(out)
    }

    /// Preflight and atomically publish at the original project location, without
    /// overwrite. Parent must exist; output must be outside the approved source root.
    /// File permissions are owner-only on Unix because GP4 contains a passcode.
    pub fn write_new(&self, approved_root: &Path) -> io::Result<()> {
        self.preflight(approved_root)?;
        if self.location.starts_with(absolute(approved_root)?) {
            return Err(invalid("project output must be outside source root"));
        }
        let parent = self
            .location
            .parent()
            .ok_or_else(|| invalid("project has no parent"))?;
        no_symlinks(parent)?;
        let xml = self.to_xml()?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut scratch = None;
        for _ in 0..100 {
            let path = parent.join(format!(
                ".pkg-tools-gp4-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    scratch = Some(path);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e),
            }
        }
        let scratch =
            scratch.ok_or_else(|| io::Error::other("cannot allocate GP4 scratch directory"))?;
        let file = scratch.join("project");
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options.open(&file)?;
            output.write_all(xml.as_bytes())?;
            output.sync_all()?;
            fs::hard_link(&file, &self.location)
        })();
        let _ = fs::remove_file(file);
        let _ = fs::remove_dir(scratch);
        result
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('\n', "&#10;")
        .replace('\r', "&#13;")
        .replace('\t', "&#9;")
}

fn relative_path(parent: &Path, source: &Path) -> io::Result<String> {
    let a: Vec<_> = parent.components().collect();
    let b: Vec<_> = source.components().collect();
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut path = PathBuf::new();
    for _ in common..a.len() {
        path.push("..");
    }
    for part in &b[common..] {
        path.push(part);
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("non-UTF-8 source path"))
}

pub(crate) fn sfo_identity(bytes: &[u8]) -> io::Result<Identity> {
    let sfo = psf::parse(bytes).map_err(|e| invalid(e.to_string()))?;
    if sfo.version != 0x101 {
        return Err(invalid("base authoring requires SFO 1.1"));
    }
    let value = |key: &[u8]| -> io::Result<String> {
        match sfo.get(key).map(|e| &e.value) {
            Some(psf::Value::Text(bytes)) => std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| invalid("non-UTF-8 SFO identity")),
            _ => Err(invalid("missing/text-required SFO identity field")),
        }
    };
    if value(b"CATEGORY")? != "gd" {
        return Err(invalid("only SFO CATEGORY=gd supported; updates blocked"));
    }
    let identity = Identity {
        content_id: value(b"CONTENT_ID")?,
        title_id: value(b"TITLE_ID")?,
        app_version: value(b"APP_VER")?,
        version: value(b"VERSION")?,
    };
    if !valid_content_id(&identity.content_id) || identity.title_id != identity.content_id[7..16] {
        return Err(invalid("invalid/inconsistent SFO CONTENT_ID/TITLE_ID"));
    }
    for version in [&identity.app_version, &identity.version] {
        if version.len() != 5
            || version.as_bytes()[2] != b'.'
            || !version
                .bytes()
                .enumerate()
                .all(|(i, b)| i == 2 || b.is_ascii_digit())
        {
            return Err(invalid("SFO APP_VER/VERSION must use NN.NN syntax"));
        }
    }
    Ok(identity)
}
