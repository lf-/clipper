// SPDX-FileCopyrightText: 2023 Jade Lovelace
// SPDX-FileCopyrightText: 2023 Rustls Contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0 OR ISC
// SPDX-License-Identifier: MPL-2.0

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    error::Error as StdError,
    fmt,
    sync::{Arc, RwLock},
};

use rustls_intercept::{
    internal::{
        key_schedule::{KeyScheduleHandshake, KeyScheduleTraffic},
        msgs::{
            deframer::{Deframed, MessageDeframer},
            handshake::{HandshakeMessagePayload, HandshakePayload},
            message::{Message, MessagePayload, PlainMessage},
        },
    },
    msgs::handshake::ServerExtension,
    require_handshake_msg, CommonState, Error as RustlsError, HandshakeType, Side,
    SupportedCipherSuite, Tls13CipherSuite, ALL_CIPHER_SUITES,
};

use crate::{
    chomp::IPTarget,
    key_db::{ClientRandom, KeyDB, SecretType},
    listener::{Listener, MessageMeta, SideData, TimingInfo},
};

pub mod timings {
    pub struct TlsConnectionStart;
}

pub mod side_data {
    use crate::{
        chomp::IPTarget,
        key_db::{ClientRandom, Secret, SecretType},
    };

    use super::ProtocolName;

    /// Expected to be fed into the stack when a new key is received by the
    /// keys service. The TLS decoding will use these messages to dequeue any
    /// decryptions that are pending keys.
    #[derive(Clone, Debug)]
    pub struct NewKeyReceived {
        pub typ: SecretType,
        pub client_random: ClientRandom,
        pub secret: Secret,
    }

    /// Fired by `net_decode::tls` when an EncryptedExtensions message
    /// with ALPN data is received by the client.
    #[derive(Clone, Debug)]
    pub struct ALPNCompleted {
        pub target: IPTarget,
        pub protocols: Vec<ProtocolName>,
    }
}

#[derive(Clone)]
pub struct ProtocolName(pub Vec<u8>);

impl fmt::Debug for ProtocolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProtocolName")
            .field(&misc::Show(&self.0))
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq)]
enum TLSDecodeError {
    MissingKey(ClientRandom),
    UnknownCipherSuite,
    RustlsError(RustlsError),
}

impl fmt::Display for TLSDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey(cr) => write!(
                f,
                "Missing a key to decode this flow with client_random {cr}"
            ),
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
    on_alpn_completed: &'a mut dyn FnMut(Vec<ProtocolName>),
}

macro_rules! try_giving_back {
    ($self:expr, $ex:expr $(,)?) => {
        match $ex {
            Ok(v) => v,
            Err(e) => return Err(($self, e.into())),
        }
    };
}

type NextStateOrError = Result<Box<dyn TLSState>, (Box<dyn TLSState>, TLSDecodeError)>;

trait TLSState: std::fmt::Debug + Send + Sync {
    // FIXME: how to signal to change state
    fn drive(
        self: Box<Self>,
        flow: &mut TLSFlow,
        to_client: bool,
        msg: &Message,
        common_data: CommonData<'_>,
    ) -> NextStateOrError;

    fn blocked_on_keys(&self) -> Option<ClientRandom> {
        None
    }
}

#[derive(Debug)]
struct Failed {}

impl TLSState for Failed {
    fn drive(
        self: Box<Self>,
        _flow: &mut TLSFlow,
        _to_client: bool,
        _msg: &Message,
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
        msg: &Message,
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
            let chp = try_giving_back!(
                self,
                require_handshake_msg!(
                    msg,
                    HandshakeType::ClientHello,
                    HandshakePayload::ClientHello
                )
            );

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
        msg: &Message,
        common_data: CommonData<'_>,
    ) -> NextStateOrError {
        if to_client {
            let shp = try_giving_back!(
                self,
                require_handshake_msg!(
                    msg,
                    HandshakeType::ServerHello,
                    HandshakePayload::ServerHello
                )
            );

            let client_handshake_traffic_secret = try_giving_back!(
                self,
                common_data
                    .key_db
                    .lookup_secret(
                        &self.client_random,
                        SecretType::ClientHandshakeTrafficSecret,
                    )
                    .ok_or(TLSDecodeError::MissingKey(self.client_random.clone()))
            );
            let server_handshake_traffic_secret = try_giving_back!(
                self,
                common_data
                    .key_db
                    .lookup_secret(
                        &self.client_random,
                        SecretType::ServerHandshakeTrafficSecret,
                    )
                    .ok_or(TLSDecodeError::MissingKey(self.client_random.clone()))
            );

            let suite = try_giving_back!(
                self,
                ALL_CIPHER_SUITES
                    .iter()
                    .find(|s| s.suite() == shp.cipher_suite)
                    .ok_or(TLSDecodeError::UnknownCipherSuite)
            );

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
        msg: &Message,
        common_data: CommonData<'_>,
    ) -> NextStateOrError {
        match msg.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::EncryptedExtensions,
                        payload: HandshakePayload::EncryptedExtensions(ref exts),
                    },
                encoded: _,
            } => {
                let protos: Option<Vec<_>> = exts.iter().find_map(|ext| match ext {
                    ServerExtension::Protocols(protos) => Some(
                        protos
                            .iter()
                            .map(|p| ProtocolName(p.as_ref().to_vec()))
                            .collect(),
                    ),
                    _ => None,
                });

                if let Some(protos) = protos {
                    (common_data.on_alpn_completed)(protos)
                }
            }
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::Finished,
                        payload: _,
                    },
                encoded: _,
            } => {
                // FIXME: key switching
                let client_traffic_secret = try_giving_back!(
                    self,
                    common_data
                        .key_db
                        .lookup_secret(&self.client_random, SecretType::ClientTrafficSecret0)
                        .ok_or(TLSDecodeError::MissingKey(self.client_random.clone()))
                );
                let server_traffic_secret = try_giving_back!(
                    self,
                    common_data
                        .key_db
                        .lookup_secret(&self.client_random, SecretType::ServerTrafficSecret0)
                        .ok_or(TLSDecodeError::MissingKey(self.client_random.clone()))
                );
                let exporter_secret = try_giving_back!(
                    self,
                    common_data
                        .key_db
                        .lookup_secret(&self.client_random, SecretType::ExporterSecret)
                        .ok_or(TLSDecodeError::MissingKey(self.client_random.clone()))
                );

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
                } else {
                    return Ok(Box::new(Self {
                        client_finished: true,
                        ..*self
                    }));
                }
            }
            MessagePayload::ApplicationData(ref p) => {
                (common_data.next)(to_client, p.0.clone());
            }
            _ => {}
        }
        Ok(self)
    }
}

#[derive(Debug)]
struct NeedKeys {
    next: Box<dyn TLSState>,
    client_random: ClientRandom,
}

impl TLSState for NeedKeys {
    fn drive(
        self: Box<Self>,
        flow: &mut TLSFlow,
        to_client: bool,
        msg: &Message,
        common_data: CommonData<'_>,
    ) -> NextStateOrError {
        tracing::trace!(?self.client_random, "exit NeedKeys");
        self.next.drive(flow, to_client, msg, common_data)
    }

    fn blocked_on_keys(&self) -> Option<ClientRandom> {
        Some(self.client_random.clone())
    }
}

struct TLSFlow {
    server: TLSSide,
    client: TLSSide,
    state: Box<dyn TLSState>,
}

impl TLSFlow {
    fn new() -> Self {
        Self {
            server: TLSSide::new(Side::Server),
            client: TLSSide::new(Side::Client),
            state: Box::new(ExpectClientHello {}),
        }
    }
}

// XXX: this whole queueing implementation fucking sucks yo.
// 1. Client random values may be shared by adversarial clients, which screws
//    us
// 2. We can't backpressure it so we kinda just have to store the stuff.
// 3. Splitting it into a retry layer and an execution layer is actually a good
//    idea, but we need to unify the way we deal with the buffering.

enum Queued {
    Raw(Vec<u8>),
    Message(Message),
}

/// Accepts TLS data and queues messages for which we do not have the keys.
///
/// Expects the state handling to be sufficiently idempotent that failing to
/// get keys will not severely break it.
pub struct TLSFlowTracker {
    queued: HashMap<ClientRandom, VecDeque<(MessageMeta, Queued)>>,
    downstream: TLSFlowTrackerInner,
}

#[derive(Debug)]
enum OkOrRetry<T, E> {
    Ok(T),
    Retry(E),
}

impl TLSFlowTracker {
    pub fn new(key_db: Arc<RwLock<KeyDB>>, next: Box<dyn Listener<Vec<u8>>>) -> Self {
        TLSFlowTracker {
            queued: Default::default(),
            downstream: TLSFlowTrackerInner::new(key_db, next),
        }
    }

    fn enqueue(&mut self, meta: MessageMeta, queued: Queued, client_random: ClientRandom) {
        self.queued
            .entry(client_random)
            .or_insert_with(VecDeque::new)
            .push_back((meta, queued));
    }

    fn process_queued(
        downstream: &mut TLSFlowTrackerInner,
        key_db: &RwLock<KeyDB>,
        meta: &MessageMeta,
        queued: Queued,
    ) -> OkOrRetry<(), Queued> {
        match queued {
            Queued::Raw(v) => {
                match downstream.on_data(meta.timing.clone(), meta.target, meta.to_client, v) {
                    OkOrRetry::Ok(_) => OkOrRetry::Ok(()),
                    OkOrRetry::Retry((_cr, queued)) => OkOrRetry::Retry(queued),
                }
            }
            Queued::Message(msg) => match downstream.process_message(key_db, meta, &msg) {
                OkOrRetry::Ok(_) => OkOrRetry::Ok(()),
                OkOrRetry::Retry(_) => OkOrRetry::Retry(Queued::Message(msg)),
            },
        }
    }
}

impl Listener<Vec<u8>> for TLSFlowTracker {
    fn on_data(&mut self, timing: TimingInfo, target: IPTarget, to_client: bool, data: Vec<u8>) {
        let meta = MessageMeta {
            timing: timing.clone(),
            target,
            to_client,
        };

        match self.downstream.on_data(timing, target, to_client, data) {
            OkOrRetry::Ok(()) => {}
            OkOrRetry::Retry((cr, m)) => {
                self.enqueue(meta, m, cr);
            }
        }
    }

    fn on_side_data(&mut self, data: Box<dyn SideData>) {
        // If the side data appears before the packet, the key db should
        // already contain the data, so we don't care about that case.
        //
        // If we are here we got the keys late.
        if let Some(upd) = (&*data)
            .as_any()
            .downcast_ref::<side_data::NewKeyReceived>()
        {
            tracing::debug!("new keys: {upd:?}");
            if let Some(q) = self.queued.get_mut(&upd.client_random) {
                while let Some((meta, msg)) = q.pop_front() {
                    let kdb = self.downstream.key_db.clone();

                    match Self::process_queued(&mut self.downstream, &kdb, &meta, msg) {
                        OkOrRetry::Ok(_) => continue,
                        OkOrRetry::Retry(queued) => {
                            q.push_front((meta, queued));
                            break;
                        }
                    }
                }
            }
        }
        self.downstream.next.on_side_data(data)
    }
}

// How do we deliver keys to the right connections? The key database knows
// which client_random is associated with the session. So we would want a
// second index from ClientRandom to TLSFlow, probably.
//
// Problem the second: what if the keys arrive before the data (not impossible
// but rather strange)? We need to retain key messages that we cannot yet
// associate with a connection.
//
// Problem the third: architecturally, how do we deliver new keys messages
// without blowing up the listener idea? It is especially a problem because we
// want to have pipelines where the next listener is invoked by the last, so we
// would have to retain a separate ref. Somehow. Ugh.
//
// I think that architecturally we want to be an actors model, but that can
// reveal inherent threading problems through ownership semantics. Maybe the
// next field should be an Arc<RwLock> so we can hold a ref to it.
//
// Another approach is to be able to shove arbitrary side-data through the
// listener stack. This seems conceptually fairly appealing: each listener
// calls the next and extracts the data it cares about if any. The reason I
// like this is that it keeps all the data flowing the same direction.

pub struct TLSFlowTrackerInner {
    flows: HashMap<IPTarget, TLSFlow>,
    // FIXME: should this exist, or should the whole thing be handled as
    // side data and then we just own our own?
    key_db: Arc<RwLock<KeyDB>>,
    next: Box<dyn Listener<Vec<u8>>>,
}

fn is_tls(target: &IPTarget) -> bool {
    target.server_port() == 443
}

impl TLSFlowTrackerInner {
    pub fn new(
        key_db: Arc<RwLock<KeyDB>>,
        next: Box<dyn Listener<Vec<u8>>>,
    ) -> TLSFlowTrackerInner {
        TLSFlowTrackerInner {
            flows: Default::default(),
            key_db,
            next,
        }
    }

    fn process_message(
        &mut self,
        key_db: &RwLock<KeyDB>,
        meta: &MessageMeta,
        message: &Message,
    ) -> OkOrRetry<bool, ClientRandom> {
        let mut entry = self
            .flows
            .entry(meta.target)
            .or_insert_with(|| TLSFlow::new());

        Self::do_message(
            &mut entry,
            key_db,
            &mut self.next,
            meta.to_client,
            &message,
            meta.timing.clone(),
            meta.target,
        )
    }

    fn do_message(
        entry: &mut TLSFlow,
        key_db: &RwLock<KeyDB>,
        next: &mut Box<dyn Listener<Vec<u8>>>,
        to_client: bool,
        msg: &Message,
        timing: TimingInfo,
        target: IPTarget,
    ) -> OkOrRetry<bool, ClientRandom> {
        let state = std::mem::replace(&mut entry.state, Box::new(Failed {}));
        let lock = key_db.read().unwrap();
        let start = timing.received_on_wire;
        let next = RefCell::new(next);

        let new_state = state.drive(
            entry,
            to_client,
            msg,
            CommonData {
                key_db: &*lock,
                next: &mut |to_client, data| {
                    let mut timing = timing.clone();
                    timing
                        .other_times
                        .insert::<timings::TlsConnectionStart>(start);

                    next.borrow_mut().on_data(timing, target, to_client, data);
                },
                on_alpn_completed: &mut |protos| {
                    next.borrow_mut()
                        .on_side_data(Box::new(side_data::ALPNCompleted {
                            target,
                            protocols: protos,
                        }))
                },
            },
        );

        match new_state {
            Ok(s) => {
                entry.state = s;
                return OkOrRetry::Ok(true);
            }
            Err((state, TLSDecodeError::MissingKey(cr))) => {
                // Stop immediately and let us get called again
                // with no new data when we get a relevant key.
                tracing::debug!("Missing key for client_random {cr:?}, new state: {state:?}");
                entry.state = Box::new(NeedKeys {
                    client_random: cr.clone(),
                    next: state,
                });
                return OkOrRetry::Retry(cr);
            }
            Err((_s, e)) => {
                tracing::warn!("failed while processing tls connection: {e}");
                return OkOrRetry::Ok(false);
            }
        }
    }

    fn on_data(
        &mut self,
        timing: TimingInfo,
        target: IPTarget,
        to_client: bool,
        data: Vec<u8>,
    ) -> OkOrRetry<(), (ClientRandom, Queued)> {
        if !is_tls(&target) {
            return OkOrRetry::Ok(());
        }

        let mut entry = self.flows.entry(target).or_insert_with(|| TLSFlow::new());

        if let Some(cr) = entry.state.blocked_on_keys() {
            return OkOrRetry::Retry((cr, Queued::Raw(data)));
        }

        let side = if to_client {
            &mut entry.client
        } else {
            &mut entry.server
        };

        // We don't limit this buffer. Sadly there is not a practical way of
        // managing this buffer reasonably since we can't drop data on the
        // floor.
        side.read_buffer.extend(&data);

        loop {
            // repeated due to borrowck
            let side = if to_client {
                &mut entry.client
            } else {
                &mut entry.server
            };
            // The rustls buffer will just not read anything out of our buffer if
            // it doesn't want to, which is fine.
            let _ = side.deframer.read(&mut side.read_buffer);

            let msg = side.deframe();

            match msg {
                Ok(Some(v)) => {
                    let msg = Message::try_from(v);
                    if let Ok(msg) = msg {
                        tracing::trace!(?entry.state, ?to_client, ?msg);
                        match Self::do_message(
                            &mut entry,
                            &*self.key_db,
                            &mut self.next,
                            to_client,
                            &msg,
                            timing.clone(),
                            target,
                        ) {
                            OkOrRetry::Ok(true) => continue,
                            OkOrRetry::Ok(false) => return OkOrRetry::Ok(()),
                            OkOrRetry::Retry(cr) => {
                                return OkOrRetry::Retry((cr, Queued::Message(msg)))
                            }
                        }
                    }
                }
                Ok(None) => {
                    // Nothing to do, we just have to read more data to get more
                    // frames
                    break OkOrRetry::Ok(());
                }
                Err(e) => tracing::warn!("error deframing tls: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;
    use crate::{
        chomp::{dump_pcap, EthernetChomper},
        test_support::*,
    };

    fn inorder_test(f: &[u8]) -> Vec<Received<Vec<u8>>> {
        let mut reader = Cursor::new(f);
        let key_db: Arc<RwLock<KeyDB>> = Default::default();
        let received = Arc::new(RwLock::new(Vec::new()));
        let mut chomper = tls_chomper(key_db, received.clone());

        dump_pcap(&mut reader, &mut chomper).unwrap();
        let mut lock = received.write().unwrap();
        std::mem::take(&mut *lock)
    }

    fn reorder_test<T: Listener<Vec<u8>>>(
        f: &[u8],
        make_chomper: impl FnOnce(
            Arc<RwLock<KeyDB>>,
            Arc<RwLock<Vec<Received<Vec<u8>>>>>,
        ) -> EthernetChomper<T>,
    ) -> Vec<Received<Vec<u8>>> {
        let mut reader = Cursor::new(f);
        let key_db: Arc<RwLock<KeyDB>> = Default::default();
        let received = Arc::new(RwLock::new(Vec::new()));
        let mut chomper = make_chomper(key_db, received.clone());
        let mut chomper2 = KeyMessageReorderer::default();

        dump_pcap(&mut reader, &mut chomper2).unwrap();
        chomper2.send_late_keys(&mut chomper).unwrap();
        let mut lock = received.write().unwrap();
        std::mem::take(&mut *lock)
    }

    #[test]
    fn test_decryption_inorder() {
        check(
            expect_test::expect_file!("./test_output/tls/nya_dsb_inorder"),
            &inorder_test(NYA_DSB),
        );
    }

    #[test]
    fn test_decryption_reordered_keys() {
        check(
            expect_test::expect_file!("./test_output/tls/nya_dsb_reordered"),
            &*reorder_test(NYA_DSB, tls_chomper),
        );
    }

    #[test]
    fn test_decryption_reordered_keys_dispatch() {
        // It should also work through dispatch just the same.
        check(
            expect_test::expect_file!("./test_output/tls/nya_dsb_reordered"),
            &*reorder_test(NYA_DSB, tls_chomper_dispatch),
        );
    }

    #[test]
    fn test_h2_alpn() {
        check(
            expect_test::expect_file!("./test_output/tls/h2"),
            &inorder_test(H2),
        );
    }

    #[test]
    fn test_tls13_session_resumption() {
        check(
            expect_test::expect_file!("./test_output/tls/tls13_session_resumption"),
            &inorder_test(TLS13_SESSION_RESUMPTION),
        );
    }
}
