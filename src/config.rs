use std::sync::OnceLock;

pub static KEEP_TMP: OnceLock<bool> = OnceLock::new();
