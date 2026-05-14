use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct ShclnError {
    pub message: String,
}

impl Error for ShclnError {}

impl fmt::Display for ShclnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // write!(f, "{}", self.message)
        // red colored log
        write!(f, "\x1b[0;31m{}\x1b[0m", self.message)
    }
}
