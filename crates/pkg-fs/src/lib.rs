//! Shared portable filename policy and no-follow, no-overwrite extraction output.

pub const MARKER: &str = ".pkg-tools-incomplete";

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
