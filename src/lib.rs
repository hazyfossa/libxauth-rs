mod encoding;
mod lock;

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::vec;

use crate::encoding::Family;
pub use crate::{encoding::Entry, lock::Lock};

pub type Hostname = Vec<u8>;

pub enum Target {
    // u16 (65536 cookies) is an arbitrary but reasonable limit
    Server { slot: u16 },
    Client { display_number: String },
}

impl From<Target> for String {
    fn from(value: Target) -> Self {
        match value {
            Target::Server { slot } => slot.to_string(),
            Target::Client { display_number } => display_number,
        }
    }
}

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
// TODO: do we need special memory handling here for security? zeroize on drop?
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

impl Entry {
    pub fn new(cookie: &Cookie, scope: Scope, target: Target) -> Entry {
        let (family, address) = scope.into();
        let display_number = target.into();
        let (auth_name, auth_data) = cookie.raw_data();

        Entry {
            family,
            address,
            display_number,
            auth_name,
            auth_data,
        }
    }
}

pub struct Authority(Vec<Entry>);

impl Authority {
    pub fn new(entries: Option<Vec<Entry>>) -> Self {
        Self(entries.unwrap_or_default())
    }

    pub fn add_entry(&mut self, entry: Entry) {
        self.0.push(entry);
    }

    fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = Vec::new();

        while let Some(entry) = Entry::read_from(reader)? {
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

impl IntoIterator for Authority {
    type Item = Entry;
    type IntoIter = vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub struct AuthorityFile {
    file: File,
    _lock: Option<Lock>,
}

impl AuthorityFile {
    pub fn from_existing(file: File, lock: Lock) -> io::Result<Self> {
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
        let lock = Lock::aqquire(path)?;

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

    pub fn get(&mut self) -> io::Result<Authority> {
        self.file.rewind()?;
        Authority::read_from(&mut self.file)
    }

    pub fn set(&mut self, authority: Authority) -> io::Result<()> {
        self.file.rewind()?;
        authority.write_to(&mut self.file)
    }

    pub fn append(&mut self, authority: Authority) -> io::Result<()> {
        // Holds without the append option on a file, as the file is opened locked
        self.file.seek(io::SeekFrom::End(0))?;
        authority.write_to(&mut self.file)
    }
}
