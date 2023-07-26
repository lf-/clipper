// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use std::{
    io::{BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use libfixture::{body, clap::Parser, print_resp, Error};

fn client(hostname: &str, addr: &str) -> Result<Vec<u8>, Error> {
    // FIXME: we need to do this with a self signed runtime generated cert for
    // fixturing for automated testing. todo.
    let mut root_store = rustls::RootCertStore::empty();
    if let Ok(v) = std::env::var("SSL_CERT_FILE") {
        let f = std::fs::OpenOptions::new().read(true).open(v).unwrap();
        let mut f = BufReader::new(f);
        let certs = rustls_pemfile::certs(&mut f).unwrap();
        root_store.add_parsable_certificates(&certs);
    }
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let rc_config = Arc::new(client_config);
    let mut tls = rustls::ClientConnection::new(rc_config, hostname.try_into()?)?;

    let mut conn = TcpStream::connect_timeout(
        &addr.to_socket_addrs()?.next().unwrap(),
        Duration::from_millis(500),
    )?;
    let mut stream = rustls::Stream::new(&mut tls, &mut conn);

    let mut plaintext = Vec::new();
    stream.write_all(&body(hostname))?;
    stream.read_to_end(&mut plaintext)?;

    Ok(plaintext)
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
