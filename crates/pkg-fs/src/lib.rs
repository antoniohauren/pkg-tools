//! Shared portable filename policy and no-follow, no-overwrite extraction output.

pub const MARKER: &str = ".pkg-tools-incomplete";

/// Resolve exact application paths to enumeration indices, including descendants
/// and required parents once. Input paths must come from a validated package tree.
/// Empty or unknown selections fail before extraction creates any output.
pub fn selected_indices<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    selected: &[&str],
) -> std::io::Result<Vec<usize>> {
    use std::collections::HashSet;
    use std::io::{Error, ErrorKind};

    if selected.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "empty extraction selection",
        ));
    }
    let selected: HashSet<_> = selected.iter().copied().collect();
    let mut missing = selected.clone();
    let mut required = selected.clone();
    for path in &selected {
        let mut parent = *path;
        while let Some((path, _)) = parent.rsplit_once('/') {
            required.insert(path);
            parent = path;
        }
    }
    let mut indices = Vec::new();
    for (index, path) in paths.into_iter().enumerate() {
        missing.remove(path);
        let mut included = required.contains(path);
        let mut parent = path;
        while !included {
            let Some((path, _)) = parent.rsplit_once('/') else {
                break;
            };
            included = selected.contains(path);
            parent = path;
        }
        if included {
            indices.push(index);
        }
    }
    if !missing.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "selected path is not in the package application tree",
        ));
    }
    Ok(indices)
}

pub fn valid_component(name: &str) -> bool {
    let stem = name.split('.').next().unwrap().to_ascii_uppercase();
    name.is_ascii()
        && !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && !name
            .bytes()
            .any(|b| b < 32 || b == 127 || b"/\\:<>\"|?*".contains(&b))
        && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(unix)]
pub use disk::Output;

#[cfg(unix)]
pub use disk::SourceRoot;

#[cfg(test)]
mod tests {
    use super::selected_indices;

    #[test]
    fn selection_resolves_union_and_parents_in_enumeration_order() {
        let paths = [
            "data",
            "data/nested",
            "data/nested/file",
            "data/unused",
            "database",
            "database/other",
            "empty",
        ];
        for selected in [
            vec!["data/nested/file", "data/nested", "data/nested"],
            vec!["data/nested", "data/nested/file"],
        ] {
            assert_eq!(selected_indices(paths, &selected).unwrap(), [0, 1, 2]);
        }
        assert_eq!(selected_indices(paths, &["data"]).unwrap(), [0, 1, 2, 3]);
        assert_eq!(selected_indices(paths, &["empty"]).unwrap(), [6]);
        for selected in [
            vec![],
            vec!["missing"],
            vec!["data", "missing"],
            vec!["../data"],
            vec!["data/"],
        ] {
            assert_eq!(
                selected_indices(paths, &selected).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }
}

#[cfg(unix)]
mod disk {
    use rustix::fs::{self, AtFlags, Mode, OFlags};
    use std::{
        fs::File,
        io::{self, Write},
        os::fd::OwnedFd,
        path::{Component, Path},
    };

    const DIR: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    pub struct Output(OwnedFd);

    /// Descriptor-relative read-only sources. Never follows symlinks, including
    /// root parents; regular files only. Does not freeze concurrent file edits.
    pub struct SourceRoot(OwnedFd);

    impl SourceRoot {
        pub fn open(path: &Path) -> io::Result<Self> {
            if !path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "source root must be absolute",
                ));
            }
            let mut root = fs::open("/", DIR, Mode::empty())?;
            for part in path.components() {
                match part {
                    Component::RootDir | Component::CurDir => (),
                    Component::Normal(name) => root = fs::openat(&root, name, DIR, Mode::empty())?,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "unsafe source root",
                        ));
                    }
                }
            }
            Ok(Self(root))
        }

        pub fn open_file(&self, path: &Path) -> io::Result<File> {
            let mut parent = rustix::io::dup(&self.0)?;
            let mut parts = path.components().peekable();
            while let Some(part) = parts.next() {
                let Component::Normal(name) = part else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unsafe source path",
                    ));
                };
                if parts.peek().is_some() {
                    parent = fs::openat(&parent, name, DIR, Mode::empty())?;
                } else {
                    // NONBLOCK prevents a raced FIFO replacement from hanging open.
                    let file = File::from(fs::openat(
                        &parent,
                        name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                        Mode::empty(),
                    )?);
                    if !file.metadata()?.is_file() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "source must be a regular file",
                        ));
                    }
                    return Ok(file);
                }
            }
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty source path",
            ))
        }
    }

    impl Output {
        /// Create a new root. Parents must exist and may not contain symlinks or `..`.
        pub fn create(path: &Path) -> io::Result<Self> {
            let mut parts = path.components().peekable();
            let mut parent = fs::open(
                if path.is_absolute() { "/" } else { "." },
                DIR,
                Mode::empty(),
            )?;
            let name = loop {
                match parts.next() {
                    Some(Component::RootDir | Component::CurDir) => {}
                    Some(Component::Normal(name)) if parts.peek().is_none() => break name,
                    Some(Component::Normal(name)) => {
                        parent = fs::openat(&parent, name, DIR, Mode::empty())?
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "unsafe output path",
                        ));
                    }
                }
            };
            fs::mkdirat(&parent, name, Mode::RWXU)?;
            fs::openat(&parent, name, DIR, Mode::empty())
                .map(Self)
                .map_err(|e| {
                    io::Error::other(format!("incomplete extraction at {}: {e}", path.display()))
                })
        }

        pub fn mark_incomplete(&self) -> io::Result<()> {
            self.create_file(super::MARKER)?
                .write_all(b"Extraction incomplete. Remove this tree before retrying.\n")
        }

        fn parent<'a>(&self, path: &'a str) -> io::Result<(OwnedFd, &'a str)> {
            let mut parts = path.split('/').peekable();
            let mut parent = rustix::io::dup(&self.0)?;
            loop {
                let name = parts.next().unwrap();
                if !super::valid_component(name) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unsafe entry path",
                    ));
                }
                if parts.peek().is_none() {
                    return Ok((parent, name));
                }
                parent = fs::openat(&parent, name, DIR, Mode::empty())?;
            }
        }

        pub fn create_directory(&self, path: &str) -> io::Result<()> {
            let (parent, name) = self.parent(path)?;
            Ok(fs::mkdirat(&parent, name, Mode::RWXU)?)
        }

        pub fn create_file(&self, path: &str) -> io::Result<File> {
            let (parent, name) = self.parent(path)?;
            Ok(File::from(fs::openat(
                &parent,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?))
        }

        pub fn finish(self) -> io::Result<()> {
            Ok(fs::unlinkat(&self.0, super::MARKER, AtFlags::empty())?)
        }
    }
}
