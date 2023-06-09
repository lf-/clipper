use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hostname = "jade.fyi";

    let addr = (hostname, 443u16).to_socket_addrs()?.next().unwrap();

    // FIXME: we need to do this with a self signed runtime generated cert for
    // fixturing for automated testing. todo.
    let mut root_store = rustls::RootCertStore::empty();
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

    let mut conn = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    let mut stream = rustls::Stream::new(&mut tls, &mut conn);

    let mut plaintext = Vec::new();
    stream.write_all(
        concat!(
            "GET /robots.txt HTTP/1.1\r\n",
            "Host: jade.fyi\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: utf-8\r\n",
            "\r\n"
        )
        .as_bytes(),
    )?;
    stream.read_to_end(&mut plaintext)?;

    let plaintext = std::str::from_utf8(&plaintext)?;

    println!("plaintext: {plaintext}");

    Ok(())
}
