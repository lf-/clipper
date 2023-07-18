// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Chrome Devtools Protocol implementation, application code

use std::{
    collections::{BTreeMap, VecDeque},
    fmt, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use base64::Engine;
use devtools_server::{
    cdp::cdp::browser_protocol::{
        network::{self, EventRequestWillBeSent},
        security,
    },
    cdp_types::{self, MethodCall},
    ConnectionStream,
};
use futures::{Stream, StreamExt};
use http::{
    header::{self},
    HeaderMap,
};
use net_decode::{
    chomp,
    http::HTTPStreamEvent,
    http::RequestId as NdRequestId,
    key_db::KeyDB,
    listener::{Listener, Nanos, TimingInfo},
};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::{chomper, Error};

pub const DEVTOOLS_PORT_RANGE: (u16, u16) = (6830, 6840);

#[derive(Debug)]
pub struct DevtoolsProtoEvent {
    timing: TimingInfo,
    inner: DevtoolsProtoEventInner,
}

pub enum DevtoolsProtoEventInner {
    /// This is split from [`HTTPStreamEvent`] since Devtools protocol expects
    /// to know the request bodies at the start of a request. This is not
    /// actually something we do natively, so we need to collect it and
    /// reconstruct it first.
    NewRequest {
        id: NdRequestId,
        body: Option<Vec<u8>>,
        parts: http::request::Parts,
    },
    NewResponse(NdRequestId, http::response::Parts),
    RespBodyChunk(NdRequestId, Vec<u8>),
    ResponseFinished(NdRequestId, usize),
}

impl fmt::Debug for DevtoolsProtoEventInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewRequest { id, body: _, parts } => {
                f.debug_tuple("NewRequest").field(id).field(parts).finish()
            }
            Self::NewResponse(id, parts) => {
                f.debug_tuple("NewResponse").field(id).field(parts).finish()
            }
            Self::RespBodyChunk(id, chunk) => f
                .debug_struct("RespBodyChunk")
                .field("id", id)
                .field("len", &chunk.len())
                .finish(),
            Self::ResponseFinished(id, len) => f
                .debug_struct("ResponseFinished")
                .field("id", id)
                .field("len", len)
                .finish(),
        }
    }
}

/// Structure to buffer events so that new clients will get all the history on
/// connection.
struct EventBuffer<T: Send> {
    new_events: broadcast::Sender<Arc<T>>,
    backlog: Arc<RwLock<VecDeque<Arc<T>>>>,
    backlog_capacity: usize,
}

impl<T: Send> EventBuffer<T> {
    fn new(capacity: usize, backlog_capacity: usize) -> Self {
        Self {
            new_events: broadcast::channel(capacity).0,
            backlog_capacity,
            backlog: Default::default(),
        }
    }

    fn send(&self, msg: T) {
        let msg = Arc::new(msg);

        {
            let mut lock = self.backlog.write().unwrap();
            lock.push_back(msg.clone());
            let excess_elements = lock.len().saturating_sub(self.backlog_capacity);
            let _ = lock.drain(..excess_elements);
        }

        // We don't care if anyone gets it.
        let _ = self.new_events.send(msg);
    }

    pub fn receiver(&self) -> impl Stream<Item = Arc<T>> {
        let backlog = self.backlog.clone();
        let pos = 0usize;
        let end_pos = backlog.read().unwrap().len();
        let mut new_items = self.new_events.subscribe();

        async_stream::stream! {
            for remain in pos..end_pos {
                let item = {
                    let lock = backlog.read().unwrap();
                    lock[remain].clone()
                };
                yield item;
            }

            loop {
                let value = new_items.recv().await;

                match value {
                    Ok(v) => yield v,
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

fn to_cdp_headers(hm: &HeaderMap) -> network::Headers {
    let deduped = hm
        .iter()
        .filter_map(|(name, val)| {
            Some((
                name.to_string(),
                serde_json::Value::String(String::from_utf8(val.as_bytes().to_vec()).ok()?),
            ))
        })
        .collect();
    network::Headers::new(serde_json::Value::Object(deduped))
}

fn to_chrome_proto_version(ver: http::Version) -> Option<&'static str> {
    Some(if ver == http::Version::HTTP_09 {
        "http/0.9"
    } else if ver == http::Version::HTTP_10 {
        "http/1.0"
    } else if ver == http::Version::HTTP_11 {
        "http/1.1"
    } else if ver == http::Version::HTTP_2 {
        "h2"
    } else if ver == http::Version::HTTP_3 {
        "h3"
    } else {
        return None;
    })
}

#[derive(Default)]
struct ResponseBodyTracker {
    requests: BTreeMap<NdRequestId, Vec<u8>>,
}

impl ResponseBodyTracker {
    fn on_chunk(&mut self, request_id: NdRequestId, chunk: &[u8]) {
        let entry = self.requests.entry(request_id).or_default();
        entry.extend(chunk);
    }

    fn data(&self, request_id: NdRequestId) -> Option<&[u8]> {
        self.requests.get(&request_id).map(|v| v.as_slice())
    }
}

fn nanos_to_seconds(nanos: Nanos) -> f64 {
    nanos as f64 / 1_000_000_000.
}

fn nanos_to_monotonic(nanos: Nanos) -> network::MonotonicTime {
    network::MonotonicTime::new(nanos_to_seconds(nanos))
}

struct ClientState {
    network_enabled: bool,
    response_bodies: Arc<RwLock<ResponseBodyTracker>>,
}

impl ClientState {
    async fn handle_conn(
        &mut self,
        mut conn: devtools_server::ServerConnection,
        recv: impl Stream<Item = Arc<DevtoolsProtoEvent>>,
        cancel: CancellationToken,
    ) -> Result<(), devtools_server::Error> {
        tokio::pin!(recv);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    return Ok(());
                }
                msg = conn.next() => {
                    match msg {
                        Some(msg) => self.handle_msg(msg?, &mut conn).await?,
                        None => return Ok(()),
                    }
                }
                msg = recv.next(), if self.network_enabled => {
                    match msg {
                        Some(msg) => self.dispatch_event(&msg, &mut conn).await?,
                        None => return Ok(()),
                    }
                }
            }
        }
    }

    async fn handle_msg(
        &mut self,
        msg: MethodCall,
        conn: &mut devtools_server::ServerConnection,
    ) -> Result<(), Error> {
        tracing::debug!("msg {msg:?}");

        match &*msg.method {
            // due to: https://github.com/rust-lang/rust/issues/76001
            // I cannot have inline const pats. that's sad.
            //
            // const { network::EnableParams::IDENTIFIER }
            "Network.enable" => {
                self.network_enabled = true;
                conn.reply(msg.id, serde_json::Value::Object(Default::default()))
                    .await?
            }
            // const { network::GetResponseBodyParams::IDENTIFIER }
            "Network.getResponseBody" => {
                // FIXME: error handling is bad, it should throw something back
                // at the caller
                let data: network::GetResponseBodyParams = serde_json::from_value(msg.params)?;
                let body = {
                    let lock = self.response_bodies.read().unwrap();
                    lock.data(u64::from_str_radix(data.request_id.inner(), 10)?)
                        // So, devtools will only preview things if they have
                        // appropriate mime types attached for what they are.
                        // We do not do any of this at present.
                        //
                        // I can assume that the browsers *probably* look at
                        // content-type and set the mime type field
                        // accordingly, but that doesn't quite add up since
                        // they'd also to sniff if the server sent garbage but
                        // the new request event happens before you have a
                        // body?
                        .map(|data| {
                            if let Ok(r) = std::str::from_utf8(data) {
                                (false, r.to_string())
                            } else {
                                (true, base64::engine::general_purpose::STANDARD.encode(data))
                            }
                        })
                };

                if let Some((base64_encoded, body)) = body {
                    let resp = network::GetResponseBodyReturns {
                        body,
                        base64_encoded,
                    };
                    conn.reply(msg.id, serde_json::to_value(&resp)?).await?;
                } else {
                    conn.send(cdp_types::Message::Response(cdp_types::Response {
                        id: msg.id,
                        result: None,
                        error: Some(cdp_types::Error {
                            code: -1,
                            message: "data not available".to_string(),
                        }),
                    }))
                    .await?
                }
            }
            _ => {
                conn.send(cdp_types::Message::Response(cdp_types::Response {
                    id: msg.id,
                    result: None,
                    error: Some(cdp_types::Error {
                        code: devtools_server::METHOD_NOT_FOUND,
                        message: "method not found".to_string(),
                    }),
                }))
                .await?
            }
        }
        Ok(())
    }

    async fn dispatch_event(
        &mut self,
        msg: &DevtoolsProtoEvent,
        conn: &mut devtools_server::ServerConnection,
    ) -> Result<(), Error> {
        tracing::debug!("event {msg:?}");

        let timestamp = nanos_to_monotonic(msg.timing.received_on_wire);
        match &msg.inner {
            DevtoolsProtoEventInner::NewRequest { id, parts, body } => {
                let ev = EventRequestWillBeSent {
                    request_id: network::RequestId::from(id.to_string()),
                    loader_id: network::LoaderId::from("".to_string()),
                    document_url: "".to_string(),
                    request: network::Request {
                        // TODO: this is missing the domain name, thats fucked
                        url: parts.uri.to_string(),
                        method: parts.method.to_string(),
                        url_fragment: None,
                        headers: to_cdp_headers(&parts.headers),
                        // TODO: we take post data in as a separate event, so
                        // these need coalescing before they go in. gah.
                        post_data: body
                            .as_ref()
                            .map(|b| String::from_utf8_lossy(b).to_string()),
                        has_post_data: body.as_ref().map(|_| true),
                        post_data_entries: None,
                        mixed_content_type: None,
                        initial_priority: network::ResourcePriority::Medium,
                        referrer_policy: network::RequestReferrerPolicy::Origin,
                        is_link_preload: None,
                        trust_token_params: None,
                        is_same_site: None,
                    },
                    timestamp,
                    wall_time: network::TimeSinceEpoch::new(nanos_to_seconds(
                        msg.timing.received_on_wire,
                    )),
                    initiator: network::Initiator {
                        r#type: network::InitiatorType::Other,
                        stack: None,
                        url: None,
                        line_number: None,
                        column_number: None,
                        request_id: None,
                    },
                    redirect_has_extra_info: false,
                    redirect_response: None,
                    r#type: None,
                    frame_id: None,
                    has_user_gesture: None,
                };

                // FIXME: do we actually need to send this event?
                // let ev2 = network::EventRequestWillBeSentExtraInfo {
                //     request_id: network::RequestId::new(id.to_string()),
                //     associated_cookies: Vec::new(),
                //     headers: to_cdp_headers(&parts.headers),
                //     connect_timing: network::ConnectTiming { request_time: 0. },
                //     client_security_state: None,
                // };

                conn.send_event(ev).await?;
                // conn.send_event(ev2).await?;
            }
            DevtoolsProtoEventInner::NewResponse(id, parts) => {
                let ev = network::EventResponseReceived {
                    request_id: network::RequestId::new(id.to_string()),
                    loader_id: network::LoaderId::new(""),
                    timestamp,
                    r#type: network::ResourceType::Other,
                    response: network::Response {
                        url: "".to_string(),
                        status: parts.status.as_u16() as _,
                        // FIXME: we have this data
                        status_text: "".to_string(),
                        headers: to_cdp_headers(&parts.headers),
                        // I am not sure if this is right, I imagine that
                        // mime types have different format to
                        // Content-Type, but yolo!
                        mime_type: parts
                            .headers
                            .get(header::CONTENT_TYPE)
                            .and_then(|s| s.to_str().ok())
                            .map(|s| s.to_string())
                            .unwrap_or_else(String::new),
                        // FIXME: do we need these?
                        request_headers: None,
                        // FIXME: we can probably find this out
                        connection_reused: false,
                        connection_id: 0.,
                        // FIXME: we definitely have this
                        remote_ip_address: None,
                        remote_port: None,
                        from_disk_cache: None,
                        from_service_worker: None,
                        from_prefetch_cache: None,
                        encoded_data_length: 0.,
                        timing: None,
                        service_worker_response_source: None,
                        response_time: None,
                        cache_storage_cache_name: None,
                        protocol: to_chrome_proto_version(parts.version).map(|s| s.to_string()),
                        security_state: security::SecurityState::Neutral,
                        security_details: None,
                    },
                    has_extra_info: false,
                    frame_id: None,
                };

                conn.send_event(ev).await?;
            }
            DevtoolsProtoEventInner::RespBodyChunk(id, data) => {
                let ev = network::EventDataReceived {
                    request_id: network::RequestId::new(id.to_string()),
                    timestamp,
                    data_length: data.len() as i64,
                    encoded_data_length: data.len() as i64,
                };

                conn.send_event(ev).await?;
            }
            DevtoolsProtoEventInner::ResponseFinished(id, len) => {
                let ev = network::EventLoadingFinished {
                    request_id: network::RequestId::new(id.to_string()),
                    timestamp,
                    // wtf, f64
                    encoded_data_length: *len as f64,
                    should_report_corb_blocking: None,
                };

                conn.send_event(ev).await?;
            }
        }
        Ok(())
    }
}

pub struct DevtoolsListener {
    send: Arc<EventBuffer<DevtoolsProtoEvent>>,
    response_bodies: Arc<RwLock<ResponseBodyTracker>>,
    requests_inflight: BTreeMap<NdRequestId, (http::request::Parts, Option<Vec<u8>>)>,
}

impl Listener<HTTPStreamEvent> for DevtoolsListener {
    fn on_data(
        &mut self,
        timing: TimingInfo,
        _target: net_decode::chomp::IPTarget,
        _to_client: bool,
        data: HTTPStreamEvent,
    ) {
        tracing::trace!(?data, "stream event");
        match data {
            HTTPStreamEvent::NewRequest(id, parts) => {
                self.requests_inflight.entry(id).or_insert((parts, None));
            }
            HTTPStreamEvent::ReqBodyChunk(id, data) => {
                let (_parts, body) = self
                    .requests_inflight
                    .get_mut(&id)
                    .expect("request inflight got chunk for bad request");

                if body.is_none() {
                    *body = Some(Vec::new());
                }

                body.as_mut().map(|d| d.extend_from_slice(&data));
            }
            HTTPStreamEvent::RequestFinished(id, _len) => {
                let (parts, body) = self
                    .requests_inflight
                    .remove(&id)
                    .expect("bad requests inflight remove");
                self.send.send(DevtoolsProtoEvent {
                    timing,
                    inner: DevtoolsProtoEventInner::NewRequest { id, body, parts },
                })
            }
            HTTPStreamEvent::NewResponse(id, parts) => {
                self.send.send(DevtoolsProtoEvent {
                    timing,
                    inner: DevtoolsProtoEventInner::NewResponse(id, parts),
                });
            }
            HTTPStreamEvent::RespBodyChunk(id, data) => {
                self.response_bodies.write().unwrap().on_chunk(id, &data);
                self.send.send(DevtoolsProtoEvent {
                    timing,
                    inner: DevtoolsProtoEventInner::RespBodyChunk(id, data),
                });
            }
            HTTPStreamEvent::ResponseFinished(id, len) => {
                self.send.send(DevtoolsProtoEvent {
                    timing,
                    inner: DevtoolsProtoEventInner::ResponseFinished(id, len),
                });
            }
        }
    }

    fn on_side_data(&mut self, _data: Box<dyn net_decode::listener::SideData>) {}
}

pub async fn do_devtools_server_inner(file: PathBuf) -> Result<(), devtools_server::Error> {
    let key_db = Arc::new(RwLock::new(KeyDB::default()));
    let (devtools_listener, bits) = make_devtools_listener();
    let mut chomper = chomper(Box::new(devtools_listener), key_db.clone());
    chomp::dump_pcap_file(file, &mut chomper)?;

    let cancel = CancellationToken::new();
    let h = run_devtools_server(bits, cancel.clone(), DEVTOOLS_PORT_RANGE);

    loop {
        tokio::select! {
            r = h => {
                cancel.cancel();
                return r;
            }
            _ = tokio::signal::ctrl_c() => {
                cancel.cancel();
                return Ok(());
            }
        }
    }
}

pub struct ListenerBits {
    event_buffer: Arc<EventBuffer<DevtoolsProtoEvent>>,
    response_bodies: Arc<RwLock<ResponseBodyTracker>>,
}

pub fn make_devtools_listener() -> (DevtoolsListener, ListenerBits) {
    let event_buffer = Arc::new(EventBuffer::new(100, 1000));
    let response_bodies: Arc<RwLock<ResponseBodyTracker>> = Default::default();
    let devtools_listener = DevtoolsListener {
        send: event_buffer.clone(),
        response_bodies: response_bodies.clone(),
        requests_inflight: Default::default(),
    };

    (
        devtools_listener,
        ListenerBits {
            event_buffer,
            response_bodies,
        },
    )
}

async fn try_make_conn_stream(
    port_range: (u16, u16),
) -> Result<ConnectionStream, devtools_server::Error> {
    for port in port_range.0..=port_range.1 {
        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        match ConnectionStream::new(sa).await {
            Ok(s) => {
                tracing::info!("Listening on ws://127.0.0.1:{port}");
                // FIXME: We should possibly bundle devtools ourselves too, but
                // this seems like a really annoying build engineering task
                // given that the npm package chrome-devtools-frontend is useless.
                tracing::info!(
                    "Browse to this URL in Chromium to view: devtools://devtools/bundled/inspector.html?ws=localhost:{port}"
                );
                return Ok(s);
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                continue;
            }
            Err(other) => {
                return Err(other.into());
            }
        }
    }
    Err(format!(
        "Could not bind a port in range {} .. {}",
        port_range.0, port_range.1
    )
    .into())
}

pub async fn run_devtools_server(
    bits: ListenerBits,
    cancel: CancellationToken,
    port_range: (u16, u16),
) -> Result<(), devtools_server::Error> {
    let mut conns = try_make_conn_stream(port_range).await?.fuse();

    loop {
        tokio::select! {
            conn = conns.select_next_some() => {
                let conn = conn?;
                let recv = bits.event_buffer.receiver();
                let mut client_state = ClientState {
                    network_enabled: false,
                    response_bodies: bits.response_bodies.clone(),
                };
                let cancel = cancel.clone();

                tokio::spawn(async move {
                    match client_state.handle_conn(conn, recv, cancel).await {
                        Ok(()) => {}
                        Err(e) => tracing::error!("error in websocket connection: {e}"),
                    }
                });
            }
            _ = cancel.cancelled() => {
                return Ok(());
            }
        }
    }
}
