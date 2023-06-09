//! Target for the key material logs

use std::{fmt, sync::OnceLock};
pub static LOG_TARGET: OnceLock<Box<dyn LogTarget>> = OnceLock::new();

pub trait LogTarget: Send + Sync {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);
}

struct Hex<'a>(&'a [u8]);
impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:x}")?;
        }
        Ok(())
    }
}

pub struct LogTargetStdout {}

impl LogTarget for LogTargetStdout {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        println!("{label} {} {}", Hex(client_random), Hex(secret));
    }
}
