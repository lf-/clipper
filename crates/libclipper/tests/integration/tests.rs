// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use std::process::Output;

use net_decode::key_db::KeyDB;
use net_decode::key_db::SecretType;

use crate::mktest;
use crate::support::*;

#[allow(unused)]
fn test_make_ca() {
    let ca = CA::new();
    std::fs::write("ca.crt", ca.ca_cert_pem()).unwrap();
    let new_cert = ca.mint("example.com");
    std::fs::write("cert.crt", new_cert.cert_der).unwrap();
    std::fs::write("cert.key", new_cert.privkey_der).unwrap();
}

fn check_output(output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nya"));
}

fn check_keylog(keylog: &[u8]) {
    let mut db = KeyDB::default();
    let mut n_keys = 0;
    let mut got_required_secret = false;
    // FIXME: this API sucks
    db.load_key_log(keylog, &mut |cr, st, s| {
        assert!(cr.0.len() > 0);
        assert!(s.0.len() > 0);
        match st {
            SecretType::Tls12ClientMasterSecret => got_required_secret = true,
            SecretType::ClientTrafficSecret0 => got_required_secret = true,
            _ => {}
        }
        n_keys += 1;
    });
    assert!(got_required_secret);
}

fn run_checked_keylog_test(fixture: Fixture) {
    let (keylog, output) = run_keylog_test(fixture);
    println!("keylog: {}", hexdump::HexDumper::new(&keylog));
    println!("output: {output:?}");
    check_output(&output);
    check_keylog(&keylog);
}

fn test_openssl_fixture_sslkeylogfile() {
    run_checked_keylog_test(Fixture::OpenSSL)
}
mktest!(test_openssl_fixture_sslkeylogfile);

fn test_dlopen_openssl_fixture_sslkeylogfile() {
    run_checked_keylog_test(Fixture::OpenSSLDlopen)
}
mktest!(test_dlopen_openssl_fixture_sslkeylogfile);

fn test_rustls_fixture_sslkeylogfile() {
    run_checked_keylog_test(Fixture::Rustls)
}
mktest!(test_rustls_fixture_sslkeylogfile);
