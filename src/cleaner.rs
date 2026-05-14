use std::path::{Path, PathBuf};

use crate::bash::clean_bash_history;
use crate::error::ShclnError;
use crate::zsh::clean_zsh_history;

pub fn clean_home(home_path: &PathBuf, bash_history: String, zsh_history: String) {
    clean_shell(&home_path.join(bash_history), "bash", clean_bash_history);
    clean_shell(&home_path.join(zsh_history), "zsh", clean_zsh_history);
}

fn clean_shell(base_path: &Path, label: &str, cleaner: fn(&str, &str) -> Result<u32, ShclnError>) {
    if !base_path.exists() {
        return;
    }

    let history_path = base_path.display().to_string();
    let tmp_path = base_path.with_extension("bak").display().to_string();

    let removed = match cleaner(&history_path, &tmp_path) {
        Ok(removed) => removed,
        Err(err) => return println!("{}", err),
    };

    println!(
        "removed {} {} from {} history ({})",
        removed,
        if removed <= 1 { "entry" } else { "entries" },
        label,
        history_path,
    );
}
