use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crate::atomic::{self, AtomicWriter};
use crate::bash::clean_bash_history;
use crate::config::Config;
use crate::error::ShclnError;
use crate::log;
use crate::patterns::Pattern;
use crate::zsh::clean_zsh_history;

/// One history entry as stored on disk.
#[derive(Debug)]
pub struct Entry {
    /// Raw bytes, including the terminating newline. Written back verbatim so
    /// the shell keeps reading the exact format it wrote.
    pub raw: Vec<u8>,
    /// Details about the match when the entry must be removed.
    pub matched: Option<Match>,
}

/// The text and pattern that caused an entry to be removed.
#[derive(Debug)]
pub struct Match {
    pub text: String,
    pub pattern: Pattern,
}

impl Entry {
    pub fn keep(raw: Vec<u8>) -> Self {
        Self { raw, matched: None }
    }

    pub fn remove(raw: Vec<u8>, text: &str, pattern: Pattern) -> Self {
        Self {
            raw,
            matched: Some(Match {
                text: text.to_string(),
                pattern,
            }),
        }
    }
}

/// Returns whether every history file was cleaned successfully.
pub fn clean_home(config: &Config) -> bool {
    let bash_ok = clean_shell(
        &config.bash_history_path(),
        "bash",
        config,
        clean_bash_history,
    );
    let zsh_ok = clean_shell(&config.zsh_history_path(), "zsh", config, clean_zsh_history);
    bash_ok && zsh_ok
}

type Cleaner = fn(&Path, &Config) -> Result<u32, ShclnError>;

fn clean_shell(base_path: &Path, label: &str, config: &Config, cleaner: Cleaner) -> bool {
    if !base_path.exists() {
        return true;
    }

    let history_path = base_path.display();

    let removed = match cleaner(base_path, config) {
        Ok(removed) => removed,
        Err(error) => {
            log::err(&error.to_string());
            log::err(&format!("'{history_path}' was left untouched"));
            return false;
        }
    };

    log::out(&format!(
        "{} {} {} from {} history ({})",
        config.removal_verb(),
        removed,
        if removed == 1 { "entry" } else { "entries" },
        label,
        history_path,
    ));

    true
}

/// Filter a history file in two passes.
///
/// The first pass only counts and reports, so a history file with nothing to
/// remove is never rewritten at all. The second pass streams the kept entries
/// into a temporary file that replaces the history file atomically.
pub fn clean_history<F, I>(
    history_path: &Path,
    config: &Config,
    make_entries: F,
) -> Result<u32, ShclnError>
where
    F: Fn(File) -> I,
    I: Iterator<Item = Result<Entry, ShclnError>>,
{
    // a symlinked HISTFILE must keep pointing at the same file after the rename
    let io_path = fs::canonicalize(history_path).unwrap_or_else(|_| PathBuf::from(history_path));

    // pick up temporary files left behind by a run that was killed hard enough
    // to skip its own cleanup, whether or not this run ends up writing
    atomic::remove_stale_tmp_files(&io_path);

    let mut removed: u32 = 0;
    for entry in make_entries(open_history(&io_path)?) {
        let Some(matched) = entry?.matched else {
            continue;
        };
        removed += 1;
        if config.print_removals() {
            log::out(&format!(
                "{} [{}] {} ({}): {}",
                config.removal_verb(),
                matched.pattern.provider,
                matched.pattern.name,
                matched.pattern.id,
                matched.text.trim_end()
            ));
        }
    }

    if removed == 0 || config.dry_run {
        return Ok(removed);
    }

    let mut writer = AtomicWriter::new(&io_path)?;
    for entry in make_entries(open_history(&io_path)?) {
        let entry = entry?;
        if entry.matched.is_some() {
            continue;
        }
        writer.write_all(&entry.raw)?;
    }
    writer.commit()?;

    Ok(removed)
}

fn open_history(path: &Path) -> Result<File, ShclnError> {
    File::open(path).map_err(|error| ShclnError {
        message: format!("Failed to open '{}': {error}", path.display()),
    })
}
