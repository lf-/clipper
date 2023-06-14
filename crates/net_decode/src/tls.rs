// SPDX-FileCopyrightText: Rustls Contributors, Jade Lovelace
// SPDX-License-Identifier: MIT OR Apache-2.0 OR ISC
//! Decoding of TLS, fun!
//!
//! It's 50/50 on hacking the shit out of rustls or figuring out how to use
//! tls-parser, and I think that hacking the shit out of rustls is possibly the
//! way to get least surprised.

use std::{
    collections::{HashMap, VecDeque},
    error::Error as StdError,
    fmt,
    sync::{Arc, RwLock},
};

use rustls_intercept::{
    internal::{
        check,
        key_schedule::{KeyScheduleHandshake, KeyScheduleTraffic},
        msgs::{
            deframer::{Deframed, MessageDeframer},
            handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload},
            message::{Message, MessagePayload, PlainMessage},
        },
        record_layer::RecordLayer,
    },
    require_handshake_msg,
    server::Accepted,
    CommonState, ContentType, Error as RustlsError, HandshakeType, Side, SupportedCipherSuite,
    Tls13CipherSuite, ALL_CIPHER_SUITES,
};

use crate::{
    chomp::IPTarget,
    key_db::{ClientRandom, KeyDB, SecretType},
    tcp_reassemble::TCPFlowReceiver,
};

#[derive(Clone, Debug, PartialEq)]
enum TLSDecodeError {
    NoKeysAvailable,
    UnknownCipherSuite,
    RustlsError(RustlsError),
}

impl fmt::Display for TLSDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKeysAvailable => write!(f, "No keys available in key log"),
            Self::UnknownCipherSuite => write!(f, "Cipher suite is not supported"),
            Self::RustlsError(e) => fmt::Display::fmt(e, f),
        }
    }
}

impl From<RustlsError> for TLSDecodeError {
    fn from(value: RustlsError) -> Self {
        Self::RustlsError(value)
    }
}

impl StdError for TLSDecodeError {}

pub struct TLSSide {
    /// Note: mostly unused.
    common_state: CommonState,
    deframer: MessageDeframer,

    /// Buffer used to manage force feeding rustls with data (since it expects
    /// to drive the feeding process rather than be fed data).
    read_buffer: VecDeque<u8>,
}

impl TLSSide {
    fn new(side: Side) -> Self {
        Self {
            common_state: CommonState::new(side),
            deframer: MessageDeframer::default(),
            read_buffer: Default::default(),
        }
    }

    // Relatively similar to ConnectionCore::deframe, but does not send alerts
    // TODO: should we just concede and implement ConnectionCore and just not
    // send data back???
    fn deframe(&mut self) -> Result<Option<PlainMessage>, RustlsError> {
        match self.deframer.pop(&mut self.common_state.record_layer) {
            Ok(Some(Deframed {
                message,
                trial_decryption_finished,
                ..
            })) => {
                if trial_decryption_finished {
                    self.common_state.record_layer.finish_trial_decryption();
                }
                Ok(Some(message))
            }
            _ => Ok(None),
        }
    }
}

struct CommonData<'a> {
    key_db: &'a KeyDB,
    next: &'a mut dyn FnMut(bool, Vec<u8>),
}

type NextStateOrError = Result<Box<dyn TLSState>, TLSDecodeError>;

trait TLSState: std::fmt::Debug {
    // FIXME: how to signal to change state
    fn drive(
        self: Box<Self>,
        flow: &mut TLSFlow,
        to_client: bool,
        msg: Message,
        common_data: CommonData<'_>,
    ) -> NextStateOrError;
}

#[derive(Debug)]
struct Failed {}

impl TLSState for Failed {
    fn drive(
        self: Box<Self>,
        _flow: &mut TLSFlow,
        _to_client: bool,
        _msg: Message,
        _common_data: CommonData<'_>,
    ) -> NextStateOrError {
        Ok(self)
    }
}

#[derive(Debug)]
struct ExpectClientHello {}

impl TLSState for ExpectClientHello {
    fn drive(
        self: Box<Self>,
        _flow: &mut TLSFlow,
        to_client: bool,
        msg: Message,
        _common_data: CommonData<'_>,
    ) -> NextStateOrError {
        if to_client {
            // should never happen?
            tracing::warn!("got message to client in initial negotiation, wtf");
            Ok(Box::new(Failed {}))
        } else {
            // expect ClientHello
            // FIXME: how do we stop following the connection in the case that
            // something just totally falls over?
            let chp = require_handshake_msg!(
                msg,
                HandshakeType::ClientHello,
                HandshakePayload::ClientHello
            )?;

            let new_state = Box::new(ExpectServerHello {
                client_random: chp.random.into(),
            });

            Ok(new_state)
        }
    }
}

#[derive(Debug)]
struct ExpectServerHello {
    client_random: ClientRandom,
}

impl TLSState for ExpectServerHello {
    fn drive(
        self: Box<Self>,
        flow: &mut TLSFlow,
        to_client: bool,
        msg: Message,
        common_data: CommonData<'_>,
    ) -> NextStateOrError {
        if to_client {
            let shp = require_handshake_msg!(
                msg,
                HandshakeType::ServerHello,
                HandshakePayload::ServerHello
            )?;

            let client_handshake_traffic_secret = common_data
                .key_db
                .lookup_secret(
                    &self.client_random,
                    SecretType::ClientHandshakeTrafficSecret,
                )
                .ok_or(TLSDecodeError::NoKeysAvailable)?;
            let server_handshake_traffic_secret = common_data
                .key_db
                .lookup_secret(
                    &self.client_random,
                    SecretType::ServerHandshakeTrafficSecret,
                )
                .ok_or(TLSDecodeError::NoKeysAvailable)?;

            let suite = ALL_CIPHER_SUITES
                .iter()
                .find(|s| s.suite() == shp.cipher_suite)
                .ok_or(TLSDecodeError::UnknownCipherSuite)?;

            match suite {
                SupportedCipherSuite::Tls13(suite) => {
                    let ks = KeyScheduleHandshake::from_data(
                        suite,
                        &client_handshake_traffic_secret.0,
                        &server_handshake_traffic_secret.0,
                    );

                    // FIXME: early data
                    ks.install_client_handshake_secrets(false, &mut flow.client.common_state);
                    ks.install_server_handshake_secrets(&mut flow.server.common_state);

                    return Ok(Box::new(WaitForFinish {
                        suite,
                        client_random: self.client_random,
                        client_finished: false,
                        server_finished: false,
                    }));
                }
                SupportedCipherSuite::Tls12(suite) => {
                    unimplemented!("tls12 {suite:?}");
                }
            }
        } else {
            dbg!(&msg);
            unreachable!();
        }
    }
}

struct WaitForFinish {
    suite: &'static Tls13CipherSuite,
    client_random: ClientRandom,
    client_finished: bool,
    server_finished: bool,
}

impl fmt::Debug for WaitForFinish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitForFinish")
            .field("client_finished", &self.client_finished)
            .field("server_finished", &self.server_finished)
            .finish_non_exhaustive()
    }
}

impl TLSState for WaitForFinish {
    fn drive(
        self: Box<Self>,
        flow: &mut TLSFlow,
        to_client: bool,
        msg: Message,
        common_data: CommonData<'_>,
    ) -> NextStateOrError {
        match msg.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::Finished,
                        payload: _,
                    },
                encoded: _,
            } => {
                // TODO: this probably buggers up the client's keys causing the
                // server's response to be unavailable

                // FIXME: key switching
                let client_traffic_secret = common_data
                    .key_db
                    .lookup_secret(&self.client_random, SecretType::ClientTrafficSecret0)
                    .ok_or(TLSDecodeError::NoKeysAvailable)?;
                let server_traffic_secret = common_data
                    .key_db
                    .lookup_secret(&self.client_random, SecretType::ServerTrafficSecret0)
                    .ok_or(TLSDecodeError::NoKeysAvailable)?;
                let exporter_secret = common_data
                    .key_db
                    .lookup_secret(&self.client_random, SecretType::ExporterSecret)
                    .ok_or(TLSDecodeError::NoKeysAvailable)?;

                // install traffic keys
                let ks = KeyScheduleTraffic::from_data(
                    self.suite,
                    &client_traffic_secret.0,
                    &server_traffic_secret.0,
                    &exporter_secret.0,
                );

                if !to_client {
                    ks.load_keys(Side::Server, &mut flow.server.common_state);
                    ks.load_keys(Side::Client, &mut flow.client.common_state);
                    return Ok(Box::new(Self {
                        server_finished: true,
                        ..*self
                    }));
                }
            }
            MessagePayload::ApplicationData(p) => {
                (common_data.next)(to_client, p.0);
            }
            _ => {}
        }
        Ok(self)
    }
}

struct TLSFlow {
    server: TLSSide,
    client: TLSSide,
    state: Box<dyn TLSState>,
}

impl Default for TLSFlow {
    fn default() -> Self {
        Self {
            server: TLSSide::new(Side::Server),
            client: TLSSide::new(Side::Client),
            state: Box::new(ExpectClientHello {}),
        }
    }
}

pub struct TLSFlowTracker {
    flows: HashMap<IPTarget, TLSFlow>,
    // XXX: This is here because there is not an obvious way to stuff a
    // reference to changing data into a TCPFlowReceiver without either making
    // everyone receive that data (tbh, probably fine, but annoying) or doing
    // this.
    key_db: Arc<RwLock<KeyDB>>,
    next: Box<dyn TCPFlowReceiver>,
}

impl TLSFlowTracker {
    pub fn new(key_db: Arc<RwLock<KeyDB>>, next: Box<dyn TCPFlowReceiver>) -> TLSFlowTracker {
        TLSFlowTracker {
            flows: Default::default(),
            key_db,
            next,
        }
    }
}

fn is_tls(target: &IPTarget) -> bool {
    target.server_port() == 443
}

impl TCPFlowReceiver for TLSFlowTracker {
    fn on_data(&mut self, target: IPTarget, to_client: bool, data: Vec<u8>) {
        if !is_tls(&target) {
            return;
        }

        let mut entry = self.flows.entry(target).or_insert_with(Default::default);

        let side = if to_client {
            &mut entry.client
        } else {
            &mut entry.server
        };

        side.read_buffer.extend(&data);
        side.deframer.read(&mut side.read_buffer).unwrap();
        let msg = side.deframe();
        match msg {
            Ok(Some(v)) => {
                let msg = Message::try_from(v);
                if let Ok(msg) = msg {
                    tracing::debug!("msg {:?} to_client={to_client}: {:?}", &entry.state, &msg);
                    let state = std::mem::replace(&mut entry.state, Box::new(Failed {}));
                    let lock = self.key_db.read().unwrap();

                    let new_state = state.drive(
                        &mut entry,
                        to_client,
                        msg,
                        CommonData {
                            key_db: &*lock,
                            next: &mut |to_client, data| {
                                self.next.on_data(target, to_client, data);
                            },
                        },
                    );

                    match new_state {
                        Ok(s) => entry.state = s,
                        Err(e) => {
                            tracing::warn!("failed while processing tls connection: {e}");
                            return;
                        }
                    }
                }
            }
            Ok(None) => {
                // Nothing to do, we just have to read more data to get more
                // frames
            }
            Err(e) => tracing::warn!("error deframing tls: {e}"),
        }
    }
}
