use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::cleaner::{clean_history, Entry};
use crate::config::Config;
use crate::error::ShclnError;
use crate::patterns::match_line;

/// Clean a bash history file.
pub fn clean_bash_history(history_path: &Path, config: &Config) -> Result<u32, ShclnError> {
    clean_history(history_path, config, |file| {
        BashEntries::new(BufReader::new(file))
    })
}

/// Frames a bash history file into one entry per line.
///
/// Entries are handled as raw bytes: bash writes whatever was typed in the
/// locale's encoding, so a history file is not guaranteed to be valid UTF-8.
/// Undecodable bytes are replaced for matching only, the entry itself is always
/// written back verbatim.
pub struct BashEntries<R: BufRead> {
    reader: R,
}

impl<R: BufRead> BashEntries<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }
}

impl<R: BufRead> Iterator for BashEntries<R> {
    type Item = Result<Entry, ShclnError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line: Vec<u8> = Vec::new();

        match self.reader.read_until(b'\n', &mut line) {
            Ok(0) => None,
            Ok(_) => Some(Ok(match_entry(line))),
            Err(error) => Some(Err(ShclnError {
                message: format!("Failed to read history: {error}"),
            })),
        }
    }
}

fn match_entry(raw: Vec<u8>) -> Entry {
    let text = String::from_utf8_lossy(&raw).trim_end().to_string();

    match match_line(&text) {
        Some(pattern) => Entry::remove(raw, &text, pattern),
        None => Entry::keep(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(history: &[u8]) -> Vec<Vec<u8>> {
        BashEntries::new(history)
            .map(|entry| entry.unwrap().raw)
            .collect()
    }

    fn kept(history: &[u8]) -> Vec<u8> {
        BashEntries::new(history)
            .flat_map(|entry| {
                let entry = entry.unwrap();
                match entry.matched {
                    None => entry.raw,
                    Some(_) => Vec::new(),
                }
            })
            .collect()
    }

    #[test]
    fn test_entries_are_lines() {
        assert_eq!(entries(b"ls\npwd\n"), [b"ls\n".to_vec(), b"pwd\n".to_vec()]);

        // a last line without a newline is an entry of its own
        assert_eq!(entries(b"ls\npwd"), [b"ls\n".to_vec(), b"pwd".to_vec()]);
        assert_eq!(entries(b""), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn test_invalid_utf8_is_kept() {
        let history: &[u8] = b"ls\ncafe-\xff-\xfe-bad\npwd\n";
        assert_eq!(kept(history), history);
    }

    #[test]
    fn test_blank_lines_are_kept() {
        let history = b"ls\n\n\npwd\n";
        assert_eq!(kept(history), history);
    }

    #[test]
    fn test_secret_is_removed() {
        assert_eq!(kept(b"ls\nexport GITHUB_TOKEN=abc123\npwd\n"), b"ls\npwd\n");
    }

    /// A blank line used to be left in the read buffer and glued to the next
    /// entry, shifting every match by one line.
    #[test]
    fn test_blank_line_does_not_leak_into_next_entry() {
        let history = b"ls\n\nexport AWS_SECRET_ACCESS_KEY=supersecretvalue\n";

        assert_eq!(
            entries(history),
            [
                b"ls\n".to_vec(),
                b"\n".to_vec(),
                b"export AWS_SECRET_ACCESS_KEY=supersecretvalue\n".to_vec(),
            ]
        );
        assert_eq!(kept(history), b"ls\n\n");
    }

    #[test]
    fn test_read_error_is_reported() {
        struct Failing;

        impl std::io::Read for Failing {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk on fire"))
            }
        }

        let error = BashEntries::new(BufReader::new(Failing))
            .next()
            .unwrap()
            .unwrap_err();
        assert!(error.message.contains("disk on fire"));
    }
}
