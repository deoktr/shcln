use std::fs::remove_file;
use std::fs::{copy, File};
use std::io::{BufRead, BufReader, BufWriter, Write};

use crate::config::KEEP_TMP;
use crate::error::ShclnError;
use crate::patterns::rm_line;

/// Clean a zsh history file.
///
/// Zsh stores entries one per line, optionally prefixed with extended history
/// metadata (`: <timestamp>:<elapsed>;<command>`), and metafies non-printable
/// bytes with `0x83` as described at
/// <https://www.zsh.org/mla/users/2011/msg00154.html>. Multi-line commands are
/// stored with each inner newline escaped as `\\\n`.
pub fn clean_zsh_history(history_path: &str, tmp_path: &str) -> Result<u32, ShclnError> {
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
    let mut entry: Vec<u8> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf) {
            Ok(n) => n,
            Err(error) => {
                return Err(ShclnError {
                    message: format!("Failed to read line from '{tmp_path}': {error}"),
                })
            }
        };

        if n == 0 {
            if !entry.is_empty() {
                flush_zsh_entry(&entry, &mut writer, &mut removed, history_path)?;
                entry.clear();
            }
            break;
        }

        entry.extend_from_slice(&buf);

        let continues =
            entry.len() >= 2 && entry[entry.len() - 1] == b'\n' && entry[entry.len() - 2] == b'\\';

        if !continues {
            flush_zsh_entry(&entry, &mut writer, &mut removed, history_path)?;
            entry.clear();
        }
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

fn flush_zsh_entry(
    entry: &[u8],
    writer: &mut BufWriter<File>,
    removed: &mut u32,
    history_path: &str,
) -> Result<(), ShclnError> {
    let content_end = if entry.ends_with(b"\n") {
        entry.len() - 1
    } else {
        entry.len()
    };
    if content_end == 0 {
        return Ok(());
    }

    let decoded = zsh_demetafy(&entry[..content_end]);
    let cmd = strip_zsh_prefix(&decoded);
    let logical = cmd.replace("\\\n", "\n");

    let matched = logical.lines().any(rm_line);
    if matched {
        *removed += 1;
    } else {
        match writer.write_all(entry) {
            Ok(_) => (),
            Err(error) => {
                return Err(ShclnError {
                    message: format!("Failed to write line to '{history_path}': {error}"),
                })
            }
        };
    }
    Ok(())
}

/// Decode zsh metafield encoding: a `0x83` byte escapes the next byte, which is
/// XOR'd with `0x20` to recover the original.
fn zsh_demetafy(bytes: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x83 && i + 1 < bytes.len() {
            out.push(bytes[i + 1] ^ 0x20);
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Strip the `: <timestamp>:<elapsed>;` prefix used by zsh extended history.
fn strip_zsh_prefix(line: &str) -> &str {
    let Some(rest) = line.strip_prefix(": ") else {
        return line;
    };
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 || i >= bytes.len() || bytes[i] != b':' {
        return line;
    }
    let mut j = i + 1;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
    }
    if j == i + 1 || j >= bytes.len() || bytes[j] != b';' {
        return line;
    }
    &rest[j + 1..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_zsh_prefix() {
        assert_eq!(strip_zsh_prefix(": 1700000000:0;ls -al"), "ls -al");
        assert_eq!(
            strip_zsh_prefix(": 1700000000:15;export FOO=bar"),
            "export FOO=bar"
        );

        // no prefix: passthrough
        assert_eq!(strip_zsh_prefix("ls -al"), "ls -al");

        // malformed: passthrough
        assert_eq!(strip_zsh_prefix(": nope"), ": nope");
        assert_eq!(strip_zsh_prefix(": 123:abc"), ": 123:abc");
        assert_eq!(strip_zsh_prefix(": 123"), ": 123");
    }

    #[test]
    fn test_zsh_demetafy() {
        // plain ASCII is untouched
        assert_eq!(zsh_demetafy(b"hello world"), "hello world");

        // 0x83 escapes the next byte, which is XOR'd with 0x20. e.g. a tab
        // (0x09) is stored as 0x83 0x29 (0x09 ^ 0x20)
        assert_eq!(zsh_demetafy(&[b'a', 0x83, 0x29, b'b']), "a\tb");

        // a null byte is stored as 0x83 0x20
        assert_eq!(zsh_demetafy(&[0x83, 0x20]), "\0");
    }
}
