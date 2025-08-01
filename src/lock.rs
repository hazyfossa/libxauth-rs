use std::{
    fs::{OpenOptions, hard_link, remove_file},
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

fn replace_filename(mut path: PathBuf, new_filename: String) -> PathBuf {
    path.set_file_name(new_filename);
    path
}

pub struct XAuthorityLock {
    creat_path: PathBuf,
    link_path: PathBuf,
}

impl XAuthorityLock {
    pub fn aqquire(xauth_path: &Path) -> io::Result<Self> {
        let filename = xauth_path.file_name().ok_or(io::Error::new(
            io::ErrorKind::InvalidFilename,
            "xauth_path does not end with a file",
        ))?;
        let filename = filename.to_str().unwrap(); // TODO: error

        let creat_path = replace_filename(xauth_path.to_path_buf(), format!("{filename}-c"));
        // TODO: for full parity need to handle case where filesystem doesnt support hard links
        let link_path = replace_filename(xauth_path.to_path_buf(), format!("{filename}-l"));

        let lockfile = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&creat_path)?;

        drop(lockfile); // immediately close, as we don't need to interact with that file

        hard_link(&creat_path, &link_path)?;

        Ok(Self {
            creat_path,
            link_path,
        })
    }
}

impl Drop for XAuthorityLock {
    fn drop(&mut self) {
        let _ = remove_file(&self.creat_path);
        let _ = remove_file(&self.link_path);
    }
}
