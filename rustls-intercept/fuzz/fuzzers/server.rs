#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls_intercept::server::ResolvesServerCert;
use rustls_intercept::{ServerConfig, ServerConnection};

use std::io;
use std::sync::Arc;

struct Fail;

impl ResolvesServerCert for Fail {
    fn resolve(
        &self,
        _client_hello: rustls_intercept::server::ClientHello,
    ) -> Option<Arc<rustls_intercept::sign::CertifiedKey>> {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fail)),
    );
    let mut server = ServerConnection::new(config).unwrap();
    let _ = server.read_tls(&mut io::Cursor::new(data));
    let _ = server.process_new_packets();
});
