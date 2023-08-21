// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener},
    process::Output,
    sync::Arc,
};

use rcgen::{Certificate, CertificateParams, DistinguishedName, IsCa};
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub const RUSTLS_FIXTURE: &'static str = env!("CARGO_BIN_FILE_RUSTLS_FIXTURE_rustls-fixture");
pub const OPENSSL_FIXTURE: &'static str = env!("CARGO_BIN_FILE_OPENSSL_FIXTURE_openssl-fixture");
pub const OPENSSL_DLOPEN_FIXTURE: &'static str =
    env!("CARGO_BIN_FILE_DLOPEN_OPENSSL_FIXTURE_dlopen-openssl-fixture");

pub const CLIPPER_INJECT: &'static str = env!("CARGO_CDYLIB_FILE_CLIPPER_INJECT_clipper_inject");

pub enum Fixture {
    Rustls,
    OpenSSL,
    OpenSSLDlopen,
}

impl From<Fixture> for tokio::process::Command {
    fn from(value: Fixture) -> Self {
        Self::new(match value {
            Fixture::Rustls => RUSTLS_FIXTURE,
            Fixture::OpenSSL => OPENSSL_FIXTURE,
            Fixture::OpenSSLDlopen => OPENSSL_DLOPEN_FIXTURE,
        })
    }
}

pub struct CA {
    ca_cert: rcgen::Certificate,
}

pub struct NewCert {
    pub cert_der: Vec<u8>,
    pub privkey_der: Vec<u8>,
}

impl CA {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::new());

        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "catgirls, inc root ca");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        Self {
            ca_cert: Certificate::from_params(params).unwrap(),
        }
    }

    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert.serialize_pem().unwrap()
    }

    pub fn mint(&self, hostname: &str) -> NewCert {
        let params = CertificateParams::new(vec![hostname.to_string()]);
        let new_cert = Certificate::from_params(params).unwrap();

        NewCert {
            cert_der: new_cert.serialize_der_with_signer(&self.ca_cert).unwrap(),
            privkey_der: new_cert.serialize_private_key_der(),
        }
    }
}

fn make_server(port_range: (u16, u16)) -> Result<TcpListener, Error> {
    for port in port_range.0..=port_range.1 {
        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        match TcpListener::bind(sa) {
            Ok(s) => return Ok(s),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                continue;
            }
            Err(other) => return Err(other.into()),
        }
    }

    Err(format!(
        "Could not bind a port in range {} .. {}",
        port_range.0, port_range.1
    )
    .into())
}

pub fn run_keylog_test(fixture: Fixture) -> (Vec<u8>, Output) {
    let server = make_server((40000, 50000)).expect("make server");
    let server_addr = server.local_addr().unwrap();
    server.set_nonblocking(true).unwrap();

    let tempdir = tempfile::tempdir().unwrap();
    let ca_cert = tempdir.path().join("ca.crt");
    let keylogfile = tempdir.path().join("keys.log");

    let ca = CA::new();
    let cert = ca.mint("example.com");

    std::fs::write(&ca_cert, ca.ca_cert_pem()).unwrap();

    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::Certificate(cert.cert_der)],
                rustls::PrivateKey(cert.privkey_der),
            )
            .unwrap(),
    );
    let acceptor = TlsAcceptor::from(server_config);

    // FIXME: for capture tests, we will have to make this happen after the
    // child is started. Pretty annoying, but we have the hooks.

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let cancel = CancellationToken::new();

    rt.block_on(async move {
        let server_task = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                let tokio_server = tokio::net::TcpListener::from_std(server).unwrap();
                loop {
                    tokio::select! {
                        r = tokio_server.accept() => {
                            let (mut sock, _sa) = r.unwrap();
                            let acceptor = acceptor.clone();

                            let mut stream = acceptor.accept(&mut sock).await.expect("accept");

                            stream
                                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 6\r\n\r\n# nyas")
                                .await
                                .unwrap();
                            stream.shutdown().await.unwrap();
                        }
                        _ = cancel.cancelled() => {
                            break;
                        }
                    }
                }
            }
        });

        println!("port: {} tmpdir: {:?}", server_addr.port(), &tempdir.path());

        let mut proc: tokio::process::Command = fixture.into();
        let output = proc
            .env("LD_PRELOAD", CLIPPER_INJECT)
            .env("SSL_CERT_FILE", &ca_cert)
            // Make sure Nix patching doesn't cause it to read the wrong file.
            // Thanks Nix.
            .env_remove("SSL_CERT_DIR")
            .env_remove("NIX_SSL_CERT_FILE")
            .env("SSLKEYLOGFILE", &keylogfile)
            .arg("client")
            .arg("example.com")
            .arg(format!("127.0.0.1:{}", server_addr.port()))
            .output()
            .await
            .unwrap();

        if !output.status.success() {
            println!("failed: \nstdout: {}\nstderr: {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            panic!("fixture execution failed");
        }
        cancel.cancel();

        server_task.await.unwrap();

        (tokio::fs::read(&keylogfile).await.unwrap(), output)
    })
}
