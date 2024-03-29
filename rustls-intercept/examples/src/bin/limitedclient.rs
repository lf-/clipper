/// limitedclient: This example demonstrates usage of ClientConfig building
/// so that unused cryptography in rustls can be discarded by the linker.  You can
/// observe using `nm` that the binary of this program does not contain any AES code.
use std::sync::Arc;

use std::io::{stdout, Read, Write};
use std::net::TcpStream;

use rustls_intercept::OwnedTrustAnchor;

fn main() {
    let mut root_store = rustls_intercept::RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );

    let config = rustls_intercept::ClientConfig::builder()
        .with_cipher_suites(&[rustls_intercept::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256])
        .with_kx_groups(&[&rustls_intercept::kx_group::X25519])
        .with_protocol_versions(&[&rustls_intercept::version::TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = "google.com".try_into().unwrap();
    let mut conn = rustls_intercept::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("google.com:443").unwrap();
    let mut tls = rustls_intercept::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: google.com\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
