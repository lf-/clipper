// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use std::{
    io::{Read, Write},
    net::TcpStream,
};

use libfixture::{body, clap::Parser, print_resp, Error};
use openssl::ssl::{SslConnector, SslMethod};

fn client(hostname: &str, addr: &str) -> Result<Vec<u8>, Error> {
    let connector = SslConnector::builder(SslMethod::tls())?.build();

    let stream = TcpStream::connect(addr)?;
    let mut stream = connector.connect(hostname, stream)?;

    stream.write_all(&body(hostname))?;
    let mut resp = Vec::new();

    stream.read_to_end(&mut resp)?;

    Ok(resp)
}

fn main() -> Result<(), Error> {
    match libfixture::Subcommand::parse() {
        libfixture::Subcommand::Client {
            host_header,
            host_and_port,
        } => print_resp(&client(&host_header, &host_and_port)?),
    }
    Ok(())
}
