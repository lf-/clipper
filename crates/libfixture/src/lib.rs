// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

pub use clap;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(clap::Parser, Debug)]
pub enum Subcommand {
    Client {
        host_header: String,
        host_and_port: String,
    },
}

pub fn print_resp(resp: &[u8]) {
    println!("resp:\n{}", String::from_utf8_lossy(&resp));
}

pub fn body(hostname: &str) -> Vec<u8> {
    format!(
        concat!(
            "GET /robots.txt HTTP/1.1\r\n",
            "Host: {hostname}\r\n",
            "Connection: close\r\n\r\n"
        ),
        hostname = hostname
    )
    .into_bytes()
}
