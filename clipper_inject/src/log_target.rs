// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Target for the key material logs

use std::{
    fmt,
    sync::{Mutex, OnceLock},
};
pub static LOG_TARGET: OnceLock<Box<dyn LogTarget>> = OnceLock::new();

pub trait LogTarget: Send + Sync {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);
}

struct Hex<'a>(&'a [u8]);
impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

pub struct LogTargetStream<W: std::io::Write>(Mutex<W>);

impl<W: std::io::Write> LogTargetStream<W> {
    pub fn new(writer: W) -> Self {
        Self(Mutex::new(writer))
    }
}

impl<W: std::io::Write + Send + Sync> LogTarget for LogTargetStream<W> {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let mut guard = self.0.lock().unwrap();
        writeln!(&mut guard, "{label} {} {}", Hex(client_random), Hex(secret))
            .expect("writing to log target");
    }
}

#[derive(Debug)]
pub struct TLSKeyLogLine {
    pub label: String,
    pub client_random: Vec<u8>,
    pub secret: Vec<u8>,
}

pub struct LogTargetMpsc(tokio::sync::mpsc::UnboundedSender<TLSKeyLogLine>);

impl LogTargetMpsc {
    pub fn new(sender: tokio::sync::mpsc::UnboundedSender<TLSKeyLogLine>) -> Self {
        Self(sender)
    }
}

impl LogTarget for LogTargetMpsc {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let _ = self.0.send(TLSKeyLogLine {
            label: label.to_string(),
            client_random: client_random.to_vec(),
            secret: secret.to_vec(),
        });
    }
}
