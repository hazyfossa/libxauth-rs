mod encoding;
mod lock;
pub mod utils;

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::vec;

use crate::encoding::{Family, XAuthorityEntry};
pub use crate::lock::XAuthorityLock;

type DisplayNumber = String;

pub enum Target {
    // Think of this as "auth slot"
    // u16 (65536 cookies) is an arbitrary but reasonable limit
    Server(u16),
    Client(DisplayNumber),
}

impl From<Target> for String {
    fn from(value: Target) -> Self {
        match value {
            Target::Server(slot) => slot.to_string(),
            Target::Client(display) => display,
        }
    }
}

type Hostname = Vec<u8>;

pub enum Scope {
    Local(Hostname),
    Any,
}

impl From<Scope> for (Family, Hostname) {
    fn from(value: Scope) -> Self {
        match value {
            Scope::Local(hostname) => (Family::Local, hostname),
            Scope::Any => (Family::Wild, [127, 0, 0, 2].to_vec()), // TODO: address
        }
    }
}

// Technically, this should be a trait "AuthMethod"
// Practically, cookie is the only method that is currently used
// TODO: do we need speacial memory handling here for security? zeroize on drop?
pub struct Cookie([u8; Self::BYTES_LEN]);
impl Cookie {
    pub const BYTES_LEN: usize = 16; // 16 * 8 = 128 random bits
    const AUTH_NAME: &str = "MIT-MAGIC-COOKIE-1";

    pub fn new(random_bytes: [u8; Self::BYTES_LEN]) -> Self {
        Self(random_bytes)
    }

    pub fn raw_data(&self) -> (String, Vec<u8>) {
        // TODO: return &str for name?
        (Self::AUTH_NAME.to_string(), self.0.into())
    }
}

impl XAuthorityEntry {
    pub fn new(cookie: &Cookie, scope: Scope, target: Target) -> XAuthorityEntry {
        let (family, address) = scope.into();
        let display_number = target.into();
        let (auth_name, auth_data) = cookie.raw_data();

        XAuthorityEntry {
            family,
            address,
            display_number,
            auth_name,
            auth_data,
        }
    }
}

pub struct XAuthority(Vec<XAuthorityEntry>);

impl XAuthority {
    pub fn new(entries: Option<Vec<XAuthorityEntry>>) -> Self {
        Self(entries.unwrap_or_default())
    }

    pub fn add_entry(&mut self, entry: XAuthorityEntry) {
        self.0.push(entry);
    }

    fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = Vec::new();

        while let Some(entry) = XAuthorityEntry::read_from(reader)? {
            buf.push(entry);
        }

        Ok(Self(buf))
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for entry in &self.0 {
            entry.write_to(writer)?
        }

        Ok(())
    }
}

impl IntoIterator for XAuthority {
    type Item = XAuthorityEntry;
    type IntoIter = vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub struct XAuthorityFile {
    file: File,
    _lock: Option<XAuthorityLock>,
}

impl XAuthorityFile {
    pub fn from_existing(file: File, lock: XAuthorityLock) -> io::Result<Self> {
        Ok(Self {
            file,
            _lock: Some(lock),
        })
    }

    /// # Safety
    /// the caller should ensure no other process will open the same file
    /// Note that for files created by other programs, this is generraly impossible to guarantee
    /// Thus, this api is not recommended, unless you are absolutely sure what you're doing
    pub unsafe fn from_existing_unlocked(file: File) -> Self {
        Self { file, _lock: None }
    }

    fn create_inner(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .mode(0o600)
            .create_new(true)
            .open(path)
    }

    pub fn create(path: &Path) -> io::Result<Self> {
        let file = Self::create_inner(path)?;
        let lock = XAuthorityLock::aqquire(path)?;

        Ok(Self {
            file,
            _lock: Some(lock),
        })
    }

    /// # Safety
    /// the caller should ensure no other process will open the same path
    // TODO: add examples on how to guarantee that
    pub unsafe fn create_unlocked(path: &Path) -> io::Result<Self> {
        let file = Self::create_inner(path)?;
        Ok(Self { file, _lock: None })
    }

    pub fn get(&mut self) -> io::Result<XAuthority> {
        self.file.rewind()?;
        XAuthority::read_from(&mut self.file)
    }

    pub fn set(&mut self, authority: XAuthority) -> io::Result<()> {
        self.file.rewind()?;
        authority.write_to(&mut self.file)
    }

    pub fn append(&mut self, authority: XAuthority) -> io::Result<()> {
        // Holds without the append option on a file, as the file is opened locked
        self.file.seek(io::SeekFrom::End(0))?;
        authority.write_to(&mut self.file)
    }
}
