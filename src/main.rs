mod atomic;
mod bash;
mod cleaner;
mod config;
mod error;
mod log;
mod pattern_data;
mod patterns;
mod prefilter;
mod zsh;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use crate::cleaner::clean_home;
use crate::config::Config;

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

    /// Print what would be removed without writing to disk
    #[arg(long, action = clap::ArgAction::SetTrue)]
    dry_run: bool,

    /// Print removed entries while writing to disk
    #[arg(long, action = clap::ArgAction::SetTrue)]
    print_removed: bool,
}

fn main() -> ExitCode {
    let args = Cli::parse();

    let home = args.home.unwrap_or_else(|| {
        PathBuf::from(
            env::var("HOME").expect("home flag not specified and HOME env var not defined"),
        )
    });

    let config = Config {
        home,
        bash_history: args.bash_history,
        zsh_history: args.zsh_history,
        dry_run: args.dry_run,
        print_removed: args.print_removed,
    };

    log::out(&format!("cleaning home: {}", config.home.display()));

    if clean_home(&config) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
