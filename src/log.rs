use std::io::Write;

/// Print to stdout, ignoring write errors.
///
/// `println!` panics on a broken pipe, and shcln is commonly piped
/// (`shcln -n | head`, quitting `less` early). A panic used to abort a run
/// after the history file had already been truncated, so no output error may
/// ever unwind the caller.
pub fn out(message: &str) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{message}");
}

/// Print to stderr, ignoring write errors.
pub fn err(message: &str) {
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let _ = writeln!(handle, "{message}");
}
