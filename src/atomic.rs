use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::ShclnError;

/// How long a temporary file may go untouched before it is taken for the
/// leftover of a killed run.
const STALE_TMP_AGE: Duration = Duration::from_secs(60);

/// Replaces a file atomically.
///
/// The new content is written to a temporary file in the same directory, synced
/// to disk, then renamed over the target. The target is never modified, so a
/// run interrupted by a signal, a panic, a full disk, or a power cut leaves the
/// previous history file exactly as it was.
///
/// Both shells reopen `HISTFILE` by path whenever they write, so replacing the
/// inode is safe for live sessions.
pub struct AtomicWriter {
    target: PathBuf,
    tmp_path: PathBuf,
    writer: BufWriter<File>,
    committed: bool,
}

impl AtomicWriter {
    pub fn new(target: &Path) -> Result<Self, ShclnError> {
        remove_stale_tmp_files(target);

        let tmp_path = tmp_path_for(target);

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|error| ShclnError {
                message: format!("Failed to create '{}': {error}", tmp_path.display()),
            })?;

        // the temporary file becomes the history file, so keep its permissions
        // instead of the umask derived default
        if let Ok(metadata) = fs::metadata(target) {
            let _ = fs::set_permissions(&tmp_path, metadata.permissions());
        }

        Ok(Self {
            target: target.to_path_buf(),
            tmp_path,
            writer: BufWriter::new(file),
            committed: false,
        })
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), ShclnError> {
        self.writer.write_all(bytes).map_err(|error| ShclnError {
            message: format!("Failed to write '{}': {error}", self.tmp_path.display()),
        })
    }

    /// Flush, sync and rename over the target.
    pub fn commit(mut self) -> Result<(), ShclnError> {
        self.writer.flush().map_err(|error| ShclnError {
            message: format!("Failed to flush '{}': {error}", self.tmp_path.display()),
        })?;

        self.writer
            .get_ref()
            .sync_all()
            .map_err(|error| ShclnError {
                message: format!("Failed to sync '{}': {error}", self.tmp_path.display()),
            })?;

        fs::rename(&self.tmp_path, &self.target).map_err(|error| ShclnError {
            message: format!(
                "Failed to replace '{}' with '{}': {error}",
                self.target.display(),
                self.tmp_path.display()
            ),
        })?;
        self.committed = true;

        // make the rename itself durable, best effort: the history is already
        // in place and a failure here is not worth reporting as an error
        if let Some(parent) = self.target.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }
}

impl Drop for AtomicWriter {
    /// A run that did not reach `commit` must not leave a copy of the history
    /// behind.
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

fn tmp_path_for(target: &Path) -> PathBuf {
    parent_dir(target).join(format!("{}{}.tmp", tmp_prefix(target), std::process::id()))
}

fn tmp_prefix(target: &Path) -> String {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("history"));
    format!("{name}.shcln-")
}

fn is_tmp_file(target: &Path, name: &str) -> bool {
    name.starts_with(&tmp_prefix(target)) && name.ends_with(".tmp")
}

fn parent_dir(target: &Path) -> &Path {
    match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Remove temporary files left behind by a run killed before it could clean up
/// after itself.
///
/// Only files untouched for `STALE_TMP_AGE` are removed, so a concurrent run
/// keeps the temporary file it is writing to. Their content is already
/// filtered, so a leftover is clutter rather than a leak.
pub fn remove_stale_tmp_files(target: &Path) {
    let Ok(entries) = fs::read_dir(parent_dir(target)) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_tmp_file(target, name) || !is_stale(&entry) {
            continue;
        }
        let _ = fs::remove_file(entry.path());
    }
}

fn is_stale(entry: &fs::DirEntry) -> bool {
    let modified = entry
        .metadata()
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);

    is_older_than(modified, SystemTime::now())
}

fn is_older_than(modified: SystemTime, now: SystemTime) -> bool {
    now.duration_since(modified)
        .is_ok_and(|age| age > STALE_TMP_AGE)
}
