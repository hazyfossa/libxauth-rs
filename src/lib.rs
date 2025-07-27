pub mod encoding;
pub mod lock;

use std::io::{self, Seek};
use std::{env, fs::File, path::PathBuf};

use crate::encoding::{Family, XAuthority, XAuthorityEntry};
use crate::lock::XAuthorityLock;

type DisplayNumber = String;

enum Target {
    // Think of this as "auth slot"
    // u16 (65535 cookies) is an arbitrary but reasonable limit
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

type Address = Vec<u8>;

pub enum Scope {
    Local(Address),
    Any,
}

impl From<Scope> for (Family, Address) {
    fn from(value: Scope) -> Self {
        match value {
            Scope::Local(hostname) => (Family::Local, hostname),
            Scope::Any => (Family::Wild, [127, 0, 0, 2].to_vec()), // TODO: address
        }
    }
}

pub struct Cookie([u8; Self::BYTES_LEN]);
impl Cookie {
    pub const BYTES_LEN: usize = 128;
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
    fn new(cookie: &Cookie, scope: Scope, target: Target) -> XAuthorityEntry {
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

pub struct ServerAuthBuilder {
    inner: XAuthority,
    free_slot: u16,
}

impl ServerAuthBuilder {
    pub fn build() -> Self {
        Self {
            inner: XAuthority::new(None),
            free_slot: 0,
        }
    }

    pub fn allow(&mut self, cookie: &Cookie, scope: Scope) {
        self.inner.add_entry(XAuthorityEntry::new(
            cookie,
            scope,
            Target::Server(self.free_slot),
        ));
        self.free_slot += 1; // TODO: handle overflow
    }

    pub fn finish(self) -> XAuthority {
        self.inner
    }

    pub fn local(cookie: &Cookie, hostname: Vec<u8>) -> XAuthority {
        XAuthority::new(Some(vec![XAuthorityEntry::new(
            cookie,
            Scope::Local(hostname),
            Target::Server(0),
        )]))
    }
}

pub struct XAuthorityFile {
    file: File,
    _lock: Option<XAuthorityLock>,
}

impl XAuthorityFile {
    pub fn new(file: File, lock: XAuthorityLock) -> io::Result<Self> {
        Ok(Self {
            file,
            _lock: Some(lock),
        })
    }

    /// # Safety
    /// This should only be used when a caller is sure no other parties will change this file.
    pub unsafe fn new_skip_locking(file: File) -> Self {
        Self { file, _lock: None }
    }

    pub fn path() -> Option<PathBuf> {
        Some(match env::var_os("XAUTHORITY") {
            Some(path) => path.into(),
            None => env::home_dir().map(|home| home.join(".Xauthority"))?,
        })
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
        self.file.seek(io::SeekFrom::End(0))?;
        authority.write_to(&mut self.file)
    }
}
