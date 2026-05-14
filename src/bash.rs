use std::fs::{copy, remove_file, File};
use std::io::{BufRead, BufReader, BufWriter, Write};

use crate::config::KEEP_TMP;
use crate::error::ShclnError;
use crate::patterns::rm_line;

/// Clean a bash history file.
pub fn clean_bash_history(history_path: &str, tmp_path: &str) -> Result<u32, ShclnError> {
    match copy(history_path, tmp_path) {
        Ok(_) => (),
        Err(error) => {
            return Err(ShclnError {
                message: format!("Failed to copy '{history_path}' to '{tmp_path}': {error}"),
            })
        }
    };

    let history_file = match File::create(history_path) {
        Ok(file) => file,
        Err(error) => {
            return Err(ShclnError {
                message: format!("Failed to open '{history_path}': {error}"),
            })
        }
    };
    let tmp_file = match File::open(tmp_path) {
        Ok(file) => file,
        Err(error) => {
            return Err(ShclnError {
                message: format!("Failed to create '{tmp_path}': {error}"),
            })
        }
    };

    let mut writer = BufWriter::new(history_file);
    let mut reader = BufReader::new(tmp_file);

    let mut removed: u32 = 0;
    let mut line = String::new();

    loop {
        match reader.read_line(&mut line) {
            Ok(b) => {
                if b == 0 {
                    break;
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::InvalidData => {
                // ignore invalid UTF-8 errors
                println!(
                    "{}",
                    ShclnError {
                        message: format!("Failed to read line from '{tmp_path}': {error}")
                    }
                );
                continue;
            }
            Err(error) => {
                return Err(ShclnError {
                    message: format!("Failed to read line from '{tmp_path}': {error}"),
                })
            }
        }

        if line.trim_end().len() == 0 {
            continue;
        }

        if !rm_line(&line.trim_end()) {
            match writer.write(line.as_bytes()) {
                Ok(_) => (),
                Err(error) => {
                    return Err(ShclnError {
                        message: format!("Failed to write line to '{history_path}': {error}"),
                    })
                }
            };
        } else {
            removed += 1;
        }
        line.clear();
    }

    match writer.flush() {
        Ok(_) => (),
        Err(error) => {
            return Err(ShclnError {
                message: format!("Failed to flush '{history_path}': {error}"),
            })
        }
    };

    if !KEEP_TMP.get().unwrap() {
        match remove_file(tmp_path) {
            Ok(_) => (),
            Err(error) => {
                return Err(ShclnError {
                    message: format!("Failed to remove temp file '{tmp_path}': {error}"),
                })
            }
        };
    }

    Ok(removed)
}
