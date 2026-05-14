mod bash;
mod cleaner;
mod config;
mod error;
mod patterns;
mod zsh;

use std::env;
use std::path::PathBuf;

use clap::Parser;

use crate::cleaner::clean_home;
use crate::config::KEEP_TMP;

/// Remove sensitive entries from shell histories.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// User home directory [default: read HOME env]
    #[arg(long)]
    home: Option<PathBuf>,

    /// Bash history file relative to home
    #[arg(long, default_value = ".bash_history")]
    bash_history: String,

    /// Zsh history file relative to home
    #[arg(long, default_value = ".zsh_history")]
    zsh_history: String,

    /// Keep temp backup file
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    keep_tmp: bool,
}

fn main() {
    let args = Cli::parse();

    KEEP_TMP.get_or_init(|| args.keep_tmp);

    let home_path = args.home.unwrap_or_else(|| {
        PathBuf::from(
            env::var("HOME").expect("home flag not specified and HOME env var not defined"),
        )
    });

    println!("cleaning home: {}", home_path.display());

    clean_home(&home_path, args.bash_history, args.zsh_history);
}
