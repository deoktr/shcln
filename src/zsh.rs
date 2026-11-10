use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::cleaner::{clean_history, Entry};
use crate::config::Config;
use crate::error::ShclnError;
use crate::patterns::match_line;

/// Clean a zsh history file.
///
/// Zsh stores entries one per line, optionally prefixed with extended history
/// metadata (`: <timestamp>:<elapsed>;<command>`), and metafies non-printable
/// bytes with `0x83` as described at
/// <https://www.zsh.org/mla/users/2011/msg00154.html>. Multi-line commands are
/// stored with each inner newline escaped as `\\\n`.
pub fn clean_zsh_history(history_path: &Path, config: &Config) -> Result<u32, ShclnError> {
    clean_history(history_path, config, |file| {
        ZshEntries::new(BufReader::new(file))
    })
}

/// Frames a zsh history file into entries, joining the lines of a multi-line
/// command back together.
pub struct ZshEntries<R: BufRead> {
    reader: R,
    /// The next physical line, read ahead to tell a multi-line command from a
    /// command that happens to end with a backslash.
    peeked: Option<Result<Vec<u8>, ShclnError>>,
    eof: bool,
}

impl<R: BufRead> ZshEntries<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            peeked: None,
            eof: false,
        }
    }

    fn fill(&mut self) {
        if self.peeked.is_some() || self.eof {
            return;
        }

        let mut line = Vec::new();
        match self.reader.read_until(b'\n', &mut line) {
            Ok(0) => self.eof = true,
            Ok(_) => self.peeked = Some(Ok(line)),
            Err(error) => {
                self.eof = true;
                self.peeked = Some(Err(ShclnError {
                    message: format!("Failed to read history: {error}"),
                }));
            }
        }
    }
}

impl<R: BufRead> Iterator for ZshEntries<R> {
    type Item = Result<Entry, ShclnError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.fill();

        let mut raw = match self.peeked.take()? {
            Ok(line) => line,
            Err(error) => return Some(Err(error)),
        };

        while ends_with_continuation(&raw) {
            self.fill();

            let continues = match self.peeked.as_ref() {
                Some(Ok(next)) => !starts_new_entry(next),
                // end of file, or a read error surfaced by the next call
                _ => false,
            };
            if !continues {
                break;
            }

            match self.peeked.take() {
                Some(Ok(next)) => raw.extend_from_slice(&next),
                _ => break,
            }
        }

        Some(Ok(match_entry(raw)))
    }
}

fn match_entry(raw: Vec<u8>) -> Entry {
    let content_end = if raw.ends_with(b"\n") {
        raw.len() - 1
    } else {
        raw.len()
    };
    if content_end == 0 {
        return Entry::keep(raw);
    }

    let decoded = zsh_demetafy(&raw[..content_end]);
    let cmd = strip_zsh_prefix(&decoded);
    let logical = cmd.replace("\\\n", "\n");

    match logical
        .lines()
        .find_map(|line| match_line(line).map(|pattern| (line, pattern)))
    {
        Some((text, pattern)) => Entry::remove(raw, text, pattern),
        None => Entry::keep(raw),
    }
}

/// A line ending with `\\\n` escapes a newline inside a multi-line command.
///
/// A command ending with a literal backslash looks the same on disk, which is
/// ambiguous: see `starts_new_entry` for how the two are told apart.
fn ends_with_continuation(raw: &[u8]) -> bool {
    raw.ends_with(b"\\\n")
}

/// Whether the line opens a new entry rather than continuing the previous one.
///
/// With `EXTENDED_HISTORY` every entry starts with `: <timestamp>:<elapsed>;`,
/// so a line carrying that prefix cannot be the continuation of a multi-line
/// command. Without it the two cases are indistinguishable and lines ending
/// with a backslash are joined, which is what zsh itself does when reading the
/// file back.
fn starts_new_entry(line: &[u8]) -> bool {
    extended_prefix_len(line).is_some()
}

/// Length of the `: <timestamp>:<elapsed>;` prefix used by zsh extended
/// history, if the line carries one.
fn extended_prefix_len(bytes: &[u8]) -> Option<usize> {
    let rest = bytes.strip_prefix(b": ")?;

    let timestamp_end = rest.iter().position(|byte| !byte.is_ascii_digit())?;
    if timestamp_end == 0 || rest[timestamp_end] != b':' {
        return None;
    }

    let elapsed = &rest[timestamp_end + 1..];
    let elapsed_end = elapsed.iter().position(|byte| !byte.is_ascii_digit())?;
    if elapsed_end == 0 || elapsed[elapsed_end] != b';' {
        return None;
    }

    // ": " + timestamp + ":" + elapsed + ";"
    Some(2 + timestamp_end + 1 + elapsed_end + 1)
}

/// Strip the `: <timestamp>:<elapsed>;` prefix used by zsh extended history.
fn strip_zsh_prefix(line: &str) -> &str {
    match extended_prefix_len(line.as_bytes()) {
        Some(len) => &line[len..],
        None => line,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(history: &[u8]) -> Vec<Vec<u8>> {
        ZshEntries::new(history)
            .map(|entry| entry.unwrap().raw)
            .collect()
    }

    fn kept(history: &[u8]) -> Vec<u8> {
        ZshEntries::new(history)
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

    #[test]
    fn test_multiline_command_is_one_entry() {
        let history = b": 1700000000:0;echo one \\\n: not-a-prefix\n: 1700000001:0;ls\n";

        assert_eq!(
            entries(history),
            [
                b": 1700000000:0;echo one \\\n: not-a-prefix\n".to_vec(),
                b": 1700000001:0;ls\n".to_vec(),
            ]
        );
        assert_eq!(kept(history), history);
    }

    #[test]
    fn test_secret_on_any_line_of_a_multiline_command_removes_the_whole_entry() {
        // removing only the matching line would leave a dangling continuation
        // which zsh would glue to the entry below it
        let history =
            b": 1700000000:0;curl -X POST \\\n-d GITHUB_TOKEN=abc123\n: 1700000001:0;ls\n";

        assert_eq!(kept(history), b": 1700000001:0;ls\n".to_vec());
    }

    #[test]
    fn test_history_without_extended_prefix() {
        let history = b"ls\nexport GITHUB_TOKEN=abc123\npwd\n";
        assert_eq!(kept(history), b"ls\npwd\n".to_vec());
    }

    #[test]
    fn test_blank_lines_and_metafied_bytes_are_kept_verbatim() {
        let history: &[u8] = b": 1700000000:0;a\x83)b\n\n: 1700000001:0;ls\n";
        assert_eq!(kept(history), history);
    }

    #[test]
    fn test_missing_trailing_newline() {
        let history = b": 1700000000:0;ls\n: 1700000001:0;pwd";
        assert_eq!(kept(history), history);

        let history = b": 1700000000:0;ls\n: 1700000001:0;export GITHUB_TOKEN=abc";
        assert_eq!(kept(history), b": 1700000000:0;ls\n".to_vec());
    }

    #[test]
    fn test_continuation_at_end_of_file() {
        let history = b": 1700000000:0;echo one \\\n";
        assert_eq!(kept(history), history);
    }
}
