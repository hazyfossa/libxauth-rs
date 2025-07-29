use crate::{Cookie, DisplayNumber, Hostname, Scope, Target, XAuthority, XAuthorityEntry};
use std::ffi::OsString;
use std::{env, path::PathBuf};

pub struct ClientAuthorityPath(PathBuf);

impl ClientAuthorityPath {
    const ENV_KEY: &str = "XAUTHORITY";
    pub fn get_env() -> Option<Self> {
        Some(Self(env::var_os(Self::ENV_KEY)?.into()))
    }

    pub fn to_env_entry(self) -> (String, OsString) {
        (Self::ENV_KEY.to_string(), self.0.into())
    }

    pub fn get_default() -> Option<Self> {
        Some(Self(
            env::home_dir()? // TODO: proper error
                .join(".Xauthority"),
        ))
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

    pub fn allow(mut self, cookie: &Cookie, scope: Scope) -> Self {
        self.inner.add_entry(XAuthorityEntry::new(
            cookie,
            scope,
            Target::Server(self.free_slot),
        ));
        // NOTE: This technically can overflow, but extremely unlikely under reasonable use
        self.free_slot += 1;
        self
    }

    pub fn finish(self) -> XAuthority {
        self.inner
    }
}

pub struct LocalAuthorityBuilder {
    cookie: Cookie,
    hostname: Hostname,
}

impl LocalAuthorityBuilder {
    pub fn new(cookie: Cookie, hostname: Hostname) -> Self {
        Self { cookie, hostname }
    }

    pub fn build_server(&self) -> ServerAuthBuilder {
        ServerAuthBuilder::build().allow(&self.cookie, Scope::Local(self.hostname.clone()))
    }

    pub fn client(self, display: DisplayNumber) -> XAuthority {
        let entry_any =
            XAuthorityEntry::new(&self.cookie, Scope::Any, Target::Client(display.clone()));

        // NOTE: The default entry allows connecting to the local display via whatever means necessary
        // However, this is still necessary for clients which do not support Scope::Any
        // (require an explicit hostname)
        //
        // TODO: is this still relevant?
        // NOTE: another purpose to local entry might be for desktop to survive a hostname change

        let entry_local = XAuthorityEntry::new(
            &self.cookie,
            Scope::Local(self.hostname),
            Target::Client(display),
        );

        XAuthority::new(Some(vec![entry_local, entry_any]))
    }
}
