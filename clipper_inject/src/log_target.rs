// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Target for the key material logs

use std::{
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use misc::Hex;

use crate::rpc;
pub static LOG_TARGET: OnceLock<Box<dyn LogTarget>> = OnceLock::new();

pub trait LogTarget: Send + Sync {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);
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

pub struct LogTargetRpc {
    addr: PathBuf,
    sender: OnceLock<tokio::sync::mpsc::UnboundedSender<TLSKeyLogLine>>,
}

impl LogTargetRpc {
    pub fn new(addr: PathBuf) -> Self {
        Self {
            addr,
            sender: Default::default(),
        }
    }
}

impl LogTarget for LogTargetRpc {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let _ = self
            .sender
            .get_or_init(|| rpc::start(self.addr.clone()))
            .send(TLSKeyLogLine {
                label: label.to_string(),
                client_random: client_random.to_vec(),
                secret: secret.to_vec(),
            });
    }
}
