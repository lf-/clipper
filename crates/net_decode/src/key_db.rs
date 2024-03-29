// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Key database, managing the keys from SSLKEYLOGFILE like things
//!
//! <https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html>

use std::{collections::HashMap, fmt, io::Write};

use misc::Hex;

/// To avoid any unintended coupling to rustls, we use our own type for this.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientRandom(pub Vec<u8>);

impl fmt::Debug for ClientRandom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClientRandom").field(&Hex(&self.0)).finish()
    }
}

impl fmt::Display for ClientRandom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.0))
    }
}

impl From<rustls_intercept::internal::msgs::handshake::Random> for ClientRandom {
    fn from(value: rustls_intercept::internal::msgs::handshake::Random) -> Self {
        Self(value.0.into())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub Vec<u8>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secret").field(&Hex(&self.0)).finish()
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretType {
    Tls12ClientMasterSecret,
    ClientEarlyTrafficSecret,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ServerTrafficSecret0,
    ClientTrafficSecret0,
    ExporterSecret,
}

impl TryFrom<&[u8]> for SecretType {
    type Error = &'static str;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(match value {
            b"CLIENT_RANDOM" => SecretType::Tls12ClientMasterSecret,
            b"CLIENT_EARLY_TRAFFIC_SECRET" => SecretType::ClientEarlyTrafficSecret,
            b"CLIENT_HANDSHAKE_TRAFFIC_SECRET" => SecretType::ClientHandshakeTrafficSecret,
            b"SERVER_HANDSHAKE_TRAFFIC_SECRET" => SecretType::ServerHandshakeTrafficSecret,
            b"CLIENT_TRAFFIC_SECRET_0" => SecretType::ClientTrafficSecret0,
            b"SERVER_TRAFFIC_SECRET_0" => SecretType::ServerTrafficSecret0,
            b"EXPORTER_SECRET" => SecretType::ExporterSecret,
            _ => return Err("unknown secret log value"),
        })
    }
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretType::Tls12ClientMasterSecret => write!(f, "CLIENT_RANDOM"),
            SecretType::ClientEarlyTrafficSecret => write!(f, "CLIENT_EARLY_TRAFFIC_SECRET"),
            SecretType::ClientHandshakeTrafficSecret => {
                write!(f, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
            }
            SecretType::ServerHandshakeTrafficSecret => {
                write!(f, "SERVER_HANDSHAKE_TRAFFIC_SECRET")
            }
            SecretType::ClientTrafficSecret0 => write!(f, "CLIENT_TRAFFIC_SECRET_0"),
            SecretType::ServerTrafficSecret0 => write!(f, "SERVER_TRAFFIC_SECRET_0"),
            SecretType::ExporterSecret => write!(f, "EXPORTER_SECRET"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionKeys {
    keys: Vec<(SecretType, Secret)>,
}

#[derive(Clone, Debug, Default)]
pub struct KeyDB {
    keys: HashMap<ClientRandom, ConnectionKeys>,
}

impl KeyDB {
    pub fn lookup_secret(&self, client_random: &ClientRandom, typ: SecretType) -> Option<Secret> {
        self.keys
            .get(client_random)
            .and_then(|sess| {
                sess.keys
                    .iter()
                    .find_map(|(t, k)| if *t == typ { Some(k) } else { None })
            })
            .cloned()
    }

    pub fn on_secret(
        &mut self,
        client_random: ClientRandom,
        secret_type: SecretType,
        secret: Secret,
    ) {
        self.keys
            .entry(client_random)
            .and_modify(|e| e.keys.push((secret_type, secret.clone())))
            .or_insert_with(move || ConnectionKeys {
                keys: vec![(secret_type, secret)],
            });
    }

    pub fn load_key_log(
        &mut self,
        key_log: &[u8],
        on_secret: &mut impl FnMut(ClientRandom, SecretType, Secret),
    ) {
        let do_line = |line: &[u8]| -> Result<_, Box<dyn std::error::Error>> {
            if line.starts_with(b"#") {
                return Err("comment, ignore me".into());
            }
            let [ty, client_random, secret]: [&[u8]; 3] =
                match line.split(|&c| c == b' ').collect::<Vec<_>>().try_into() {
                    Ok(v) => v,
                    Err(_) => return Err("weird line".into()),
                };
            let ty = SecretType::try_from(ty)?;

            let client_random = hex::decode(client_random)?;
            let secret = hex::decode(secret)?;

            Ok((ty, client_random, secret))
        };

        // FIXME: this is not compliant, should accept \r\n also.
        for line in key_log.split(|&b| b == b'\n') {
            if let Ok((ty, client_random, secret)) = do_line(line) {
                self.on_secret(
                    ClientRandom(client_random.clone()),
                    ty,
                    Secret(secret.clone()),
                );
                on_secret(ClientRandom(client_random), ty, Secret(secret));
            }
        }
    }

    pub fn to_key_log(&self) -> Vec<u8> {
        let mut log = Vec::new();

        for (random, secrets) in &self.keys {
            for (ty, secret) in &secrets.keys {
                writeln!(log, "{} {} {}", ty, random, secret).unwrap();
            }
        }

        log
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_keydb_parsing() {
        let example = include_bytes!("testdata/sslkeylog.txt");

        let mut keydb = KeyDB::default();
        keydb.load_key_log(example, &mut |_, _, _| {});

        let hex = |s| hex::decode(s).unwrap();

        let mut hm = HashMap::new();
        hm.insert(ClientRandom(hex("37dd971034934aa6760527ef45377ef8eb8a104e4ffcd423c7e0f677f381cd19")),
            ConnectionKeys { keys: vec![
            (SecretType::ClientHandshakeTrafficSecret, Secret(hex("b6f31bb29c467e20cfb23e2a43fb5112b4f54482da454a3378ae45b783f7ff4938ce1f3c293228e58ecb3edc7ec5a72c"))),
            (SecretType::ServerHandshakeTrafficSecret, Secret(hex("6834b4927e47e97494a1d34148570efdcb0cca8bcd2b1b5d5fd1985056248f3d83c785f5837f92ce92359b1b48110690"))),
            (SecretType::ClientTrafficSecret0, Secret(hex("a10cd9a0559dd720a04970993c793a97f055dfc359671efd3e0fc04f20ff8a0328a61d89f1162762d4d0a141c7137192"))),
            (SecretType::ServerTrafficSecret0, Secret(hex("c2cb23dec467e4aed23be3969865cdd9aebbdeed7a933e8921c604264ae3bbce83a82f99cc47775d54ae09985b9b908b"))),
            (SecretType::ExporterSecret, Secret(hex("34dcd551cf060db961ecff33b3ef24a65b2c75a4857b09823653d5dac72de3aea8414beb23b4c74a340365514396ba9b")))
        ]});

        assert_eq!(&keydb.keys, &hm);
    }
}
