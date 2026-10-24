use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    /// User home directory, the base the relative history paths are joined to.
    pub home: PathBuf,
    /// Bash history file relative to `home`.
    pub bash_history: String,
    /// Zsh history file relative to `home`.
    pub zsh_history: String,
    pub dry_run: bool,
    pub print_removed: bool,
}

impl Config {
    /// Absolute path to the bash history file.
    pub fn bash_history_path(&self) -> PathBuf {
        self.home.join(&self.bash_history)
    }

    /// Absolute path to the zsh history file.
    pub fn zsh_history_path(&self) -> PathBuf {
        self.home.join(&self.zsh_history)
    }

    pub fn removal_verb(&self) -> &'static str {
        if self.dry_run {
            "would remove"
        } else {
            "removed"
        }
    }

    /// Whether removed entries may be printed.
    ///
    /// Off by default when writing to disk: under a systemd timer or a cron job
    /// stdout is captured by the journal, which would keep the very secrets
    /// shcln removes from the history file.
    pub fn print_removals(&self) -> bool {
        self.dry_run || self.print_removed
    }
}
