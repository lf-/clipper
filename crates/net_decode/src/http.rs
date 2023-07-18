// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! HTTP decoding using h2 and httparse
//!
//! FIXME:
//! - Gzip

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    fmt,
    io::{self, Write},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut};
use futures::{task::noop_waker, FutureExt};
use h2_intercept::frame::{Frame as HTTP2Frame, StreamId};
use http::{header::CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue};

use crate::{
    chomp::IPTarget,
    listener::{Listener, SideData, TimingInfo},
    tls,
};

pub type RequestId = u64;

pub enum HTTPStreamEvent {
    NewRequest(RequestId, http::request::Parts),
    ReqBodyChunk(RequestId, Vec<u8>),
    RequestFinished(RequestId, usize),
    NewResponse(RequestId, http::response::Parts),
    RespBodyChunk(RequestId, Vec<u8>),
    ResponseFinished(RequestId, usize),
}

impl fmt::Debug for HTTPStreamEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewRequest(id, parts) => {
                f.debug_tuple("NewRequest").field(id).field(parts).finish()
            }
            Self::ReqBodyChunk(id, chunk) => f
                .debug_struct("ReqBodyChunk")
                .field("id", id)
                .field("len", &chunk.len())
                .finish(),
            Self::RequestFinished(id, len) => f
                .debug_struct("RequestFinished")
                .field("id", id)
                .field("len", len)
                .finish(),
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

const MAX_HEADERS: usize = 100;

#[derive(Clone, Copy, Debug)]
enum HTTP1ParserState {
    RecvHeaders,
    Body,
    Error,
}

impl Default for HTTP1ParserState {
    fn default() -> Self {
        Self::RecvHeaders
    }
}

struct OnwardData<'a> {
    timing: TimingInfo,
    target: IPTarget,
    new_request_id: &'a mut dyn FnMut() -> RequestId,
    next: &'a mut dyn Listener<HTTPStreamEvent>,
}

#[derive(Default)]
struct FakeAsyncBufs {
    read: VecDeque<u8>,
}

impl FakeAsyncBufs {
    fn append(&mut self, buf: &[u8]) {
        self.read.write_all(buf).unwrap();
    }
}

impl tokio::io::AsyncWrite for FakeAsyncBufs {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }
}

impl tokio::io::AsyncRead for FakeAsyncBufs {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        buf.put((&mut self.get_mut().read).take(buf.remaining()));
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Copy, Debug)]
enum SideState {
    /// Expect headers.
    Headers,
    /// Expect continuation of headers.
    HeadersContinued,
    /// Expect data.
    Data,
}

#[derive(Clone, Copy, Debug)]
enum StreamState {
    Open,
    HalfClosedServer,
    HalfClosedClient,
    Closed,
    Error,
}

#[derive(Debug)]
struct Stream {
    state: StreamState,
    server: SideState,
    client: SideState,
    request_id: RequestId,
}

impl Stream {
    fn new(request_id: RequestId) -> Self {
        Self {
            state: StreamState::Open,
            server: SideState::Headers,
            client: SideState::Headers,
            request_id,
        }
    }
}

impl Stream {
    fn drive_state(
        &mut self,
        to_client: bool,
        frame: HTTP2Frame,
        on_data: &mut dyn FnMut(&mut Self, h2_intercept::frame::Data) -> Result<(), HTTPParseError>,
        on_headers: &mut dyn FnMut(
            &mut Self,
            h2_intercept::frame::Headers,
        ) -> Result<(), HTTPParseError>,
    ) -> Result<(), HTTPParseError> {
        let mut open_or_half_closed = |this: &mut Self,
                                       frame: HTTP2Frame,
                                       nexts: (StreamState, StreamState)|
         -> Result<(), HTTPParseError> {
            let side = if to_client {
                &mut this.client
            } else {
                &mut this.server
            };

            let our_next = if to_client { nexts.0 } else { nexts.1 };
            match frame {
                HTTP2Frame::Headers(hs) => {
                    assert!(!(hs.is_end_stream() && !hs.is_end_headers()), "END_STREAM + no END_HEADERS seems to never happen in rust h2 but would break our state handling");
                    *side = if hs.is_end_headers() {
                        SideState::Data
                    } else {
                        SideState::HeadersContinued
                    };

                    if hs.is_end_stream() {
                        this.state = our_next;
                    }

                    tracing::trace!(?this.state, ?hs, "got headers");
                    on_headers(this, hs)?;
                }
                HTTP2Frame::Data(d) => {
                    if d.is_end_stream() {
                        this.state = our_next;
                    }

                    tracing::trace!(?this.state, ?d, "got data");
                    on_data(this, d)?;
                }
                _ => {
                    this.state = StreamState::Error;
                }
            }
            Ok(())
        };

        match self.state {
            StreamState::Open => (open_or_half_closed)(
                self,
                frame,
                (StreamState::HalfClosedServer, StreamState::HalfClosedClient),
            )?,
            StreamState::HalfClosedClient if to_client => {
                (open_or_half_closed)(self, frame, (StreamState::Closed, StreamState::Closed))?
            }
            StreamState::HalfClosedClient => {
                // FIXME: this doesn't really account for the other side still
                // having some stuff in the queue. It's not really clear how to
                // *actually* close here.
                match frame {
                    HTTP2Frame::Reset(_) => {
                        return Ok(());
                    }
                    _ => {}
                }

                tracing::warn!(?frame, "client sent data on client-half-closed stream");
                self.state = StreamState::Error;
            }
            StreamState::HalfClosedServer if !to_client => {
                (open_or_half_closed)(self, frame, (StreamState::Closed, StreamState::Closed))?;
            }
            StreamState::HalfClosedServer => {
                match frame {
                    HTTP2Frame::Reset(_) => {
                        return Ok(());
                    }
                    _ => {}
                }
                tracing::warn!(?frame, "server sent data on server-half-closed stream");
                self.state = StreamState::Error;
            }
            StreamState::Closed => {}
            StreamState::Error => {
                // Ignore further frames once we are in error state
            }
        }
        Ok(())
    }
}

struct HTTP2Side {
    codec: h2_intercept::Codec<FakeAsyncBufs, bytes::Bytes>,
}

impl Default for HTTP2Side {
    fn default() -> Self {
        Self {
            codec: h2_intercept::Codec::new(FakeAsyncBufs::default()),
        }
    }
}

impl From<h2_intercept::Codec<FakeAsyncBufs, bytes::Bytes>> for HTTP2Side {
    fn from(codec: h2_intercept::Codec<FakeAsyncBufs, bytes::Bytes>) -> Self {
        Self { codec }
    }
}

enum HTTP2Server {
    Handshake(h2_intercept::server::ReadPreface<FakeAsyncBufs, bytes::Bytes>),
    Serve(HTTP2Side),
    Error,
}

pub struct HTTP2Flow {
    request_id: RequestId,
    streams: HashMap<StreamId, Stream>,
    client: HTTP2Side,
    server: HTTP2Server,
}

impl Default for HTTP2Flow {
    fn default() -> Self {
        Self {
            request_id: 0,
            streams: HashMap::default(),
            client: HTTP2Side::default(),
            server: HTTP2Server::Handshake(h2_intercept::server::ReadPreface::new(
                h2_intercept::Codec::new(FakeAsyncBufs::default()),
            )),
        }
    }
}

fn stream_id(f: &HTTP2Frame) -> Option<StreamId> {
    match f {
        HTTP2Frame::Data(d) => Some(d.stream_id()),
        HTTP2Frame::Headers(hs) => Some(hs.stream_id()),
        HTTP2Frame::Priority(_) => None,
        HTTP2Frame::PushPromise(pp) => Some(pp.stream_id()),
        HTTP2Frame::Settings(_) => None,
        HTTP2Frame::Ping(_) => None,
        HTTP2Frame::GoAway(_) => None,
        HTTP2Frame::WindowUpdate(_) => None,
        HTTP2Frame::Reset(r) => Some(r.stream_id()),
    }
}

fn pseudo_to_uri(
    pseudo: h2_intercept::frame::Pseudo,
) -> Result<http::uri::Uri, http::uri::InvalidUriParts> {
    let mut uri = http::uri::Parts::default();
    uri.scheme = pseudo
        .scheme
        .and_then(|s| http::uri::Scheme::try_from(s.as_bytes()).ok());
    uri.authority = pseudo
        .authority
        .and_then(|a| http::uri::Authority::try_from(a.as_bytes()).ok());
    uri.path_and_query = pseudo
        .path
        .and_then(|p| http::uri::PathAndQuery::try_from(p.as_bytes()).ok());
    uri.try_into()
}

type Streams = HashMap<StreamId, Stream>;

impl HTTP2Flow {
    fn on_h2_frame(
        streams: &mut Streams,
        frame: HTTP2Frame,
        to_client: bool,
        onward_data: &mut OnwardData<'_>,
    ) -> Result<(), HTTPParseError> {
        tracing::trace!(?frame, "h2 frame");
        if let Some(sid) = stream_id(&frame) {
            if sid == StreamId::from(0) {
                return Ok(());
            }

            let stream = streams
                .entry(sid)
                .or_insert_with(|| Stream::new((onward_data.new_request_id)()));
            tracing::trace!(?stream, ?sid, "stream state");
            let onward_data = RefCell::new(onward_data);
            stream.drive_state(
                to_client,
                frame,
                &mut |stream, data| {
                    // This feels *really* dirty and
                    // insufficiently abstracted.
                    let ev = if to_client {
                        HTTPStreamEvent::RespBodyChunk(stream.request_id, data.payload().to_vec())
                    } else {
                        HTTPStreamEvent::ReqBodyChunk(stream.request_id, data.payload().to_vec())
                    };

                    let onward_data = &mut *onward_data.borrow_mut();
                    onward_data.next.on_data(
                        onward_data.timing.clone(),
                        onward_data.target,
                        to_client,
                        ev,
                    );

                    if data.is_end_stream() {
                        // FIXME: the length reported here is meaningless
                        // but I don't know if we can ever get useful data
                        // for it
                        let msg = if to_client {
                            HTTPStreamEvent::ResponseFinished(stream.request_id, 0)
                        } else {
                            HTTPStreamEvent::RequestFinished(stream.request_id, 0)
                        };
                        onward_data.next.on_data(
                            onward_data.timing.clone(),
                            onward_data.target,
                            to_client,
                            msg,
                        )
                    }
                    Ok(())
                },
                &mut |stream, headers| {
                    let evs = if to_client {
                        let mut parts = new_resp_parts();
                        let (pseudo, hs) = headers.into_parts();
                        parts.status = pseudo.status.expect("status missing?");
                        parts.version = http::Version::HTTP_2;
                        parts.headers = hs;
                        vec![HTTPStreamEvent::NewResponse(stream.request_id, parts)]
                    } else {
                        let mut parts = new_req_parts();

                        let is_end_stream = headers.is_end_stream();
                        let (pseudo, hs) = headers.into_parts();
                        parts.version = http::Version::HTTP_2;
                        parts.headers = hs;
                        parts.method = pseudo.method.clone().unwrap_or_default();
                        parts.uri = pseudo_to_uri(pseudo)?;

                        let mut to_send =
                            vec![HTTPStreamEvent::NewRequest(stream.request_id, parts)];

                        // There is no body so the length is 0.
                        if is_end_stream {
                            to_send.push(HTTPStreamEvent::RequestFinished(stream.request_id, 0));
                        }
                        to_send
                    };

                    let onward_data = &mut *onward_data.borrow_mut();
                    for ev in evs {
                        onward_data.next.on_data(
                            onward_data.timing.clone(),
                            onward_data.target,
                            to_client,
                            ev,
                        );
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    fn feed_codec(
        data: &[u8],
        to_client: bool,
        codec: &mut h2_intercept::Codec<FakeAsyncBufs, bytes::Bytes>,
        streams: &mut Streams,
        mut onward_data: OnwardData<'_>,
    ) -> Result<(), HTTPParseError> {
        codec.get_mut().append(&data);
        let fake_waker = noop_waker();
        let mut fake_ctx = Context::from_waker(&fake_waker);
        loop {
            match futures::Stream::poll_next(Pin::new(codec), &mut fake_ctx) {
                Poll::Ready(Some(f)) => match f {
                    Ok(f) => {
                        // FIXME: this seems like bad error handling: the error
                        // should probably be caught here and not further
                        // propagated
                        Self::on_h2_frame(streams, f, to_client, &mut onward_data)?;
                    }
                    Err(err) => {
                        tracing::warn!(%err, "h2 decode error");
                    }
                },
                Poll::Ready(None) => {
                    // Need to wait for more data
                    break;
                }
                Poll::Pending => {
                    unreachable!("no async here")
                }
            }
        }
        Ok(())
    }

    fn handle_request(
        &mut self,
        to_client: bool,
        data: &mut Vec<u8>,
        onward_data: OnwardData<'_>,
    ) -> Result<(), HTTPParseError> {
        if to_client {
            Self::feed_codec(
                data,
                to_client,
                &mut self.client.codec,
                &mut self.streams,
                onward_data,
            )
        } else {
            match self.server {
                HTTP2Server::Handshake(ref mut hs) => {
                    // FIXME: how do we ensure that we get all the data
                    // required to start the handshake here?
                    hs.inner_mut().append(data);
                    let fake_waker = noop_waker();
                    let mut fake_ctx = Context::from_waker(&fake_waker);
                    match hs.poll_unpin(&mut fake_ctx) {
                        Poll::Ready(Ok(v)) => {
                            self.server = HTTP2Server::Serve(v.into());
                        }
                        Poll::Ready(Err(e)) => {
                            tracing::warn!(%e, "error in h2 handshake");
                            self.server = HTTP2Server::Error;
                        }
                        Poll::Pending => unreachable!("no async here"),
                    }
                    Ok(())
                }
                HTTP2Server::Serve(ref mut codec) => Self::feed_codec(
                    data,
                    to_client,
                    &mut codec.codec,
                    &mut self.streams,
                    onward_data,
                ),
                HTTP2Server::Error => {
                    // Already in error state, just eat packets
                    Ok(())
                }
            }
        }
    }
}

#[derive(Default)]
pub struct HTTP1Flow {
    request_id: RequestId,
    client_state: HTTP1ParserState,
    server_state: HTTP1ParserState,
    // FIXME: technically with malicious input this could waste unbounded
    // memory. maybe we should give up after a while?
    // FIXME: streaming misery
    req_buf: Vec<u8>,
    req_remain: usize,
    req_sent: usize,

    resp_buf: Vec<u8>,
    resp_remain: usize,
    resp_sent: usize,
}

fn to_header_map(headers: &[httparse::Header<'_>]) -> HeaderMap {
    let mut header_map = HeaderMap::new();
    for h in headers {
        if *h == httparse::EMPTY_HEADER {
            // XXX: surely there is a way to actually find the end of
            // this?
            break;
        }
        header_map.append(
            match HeaderName::from_bytes(h.name.as_bytes()) {
                Ok(v) => v,
                Err(err) => {
                    tracing::debug!("invalid http header {err}");
                    continue;
                }
            },
            match HeaderValue::try_from(h.value) {
                Ok(v) => v,
                Err(err) => {
                    tracing::debug!("invalid http header value: {err}");
                    continue;
                }
            },
        );
    }
    header_map
}

#[derive(Debug, thiserror::Error)]
enum HTTPParseError {
    #[error("bad http version 1.{0}")]
    BadVersion(u8),
    #[error("bad uri: {0}")]
    BadUri(#[from] http::uri::InvalidUri),
    #[error("invalid uri parts: {0}")]
    InvalidUriParts(#[from] http::uri::InvalidUriParts),
    #[error("bad method: {0}")]
    InvalidMethod(#[from] http::method::InvalidMethod),
    #[error("invalid status code: {0}")]
    InvalidStatusCode(#[from] http::status::InvalidStatusCode),
    #[error("failed to parse request: {0}")]
    ParseFailed(#[from] httparse::Error),
}

// the constructor is private
fn new_req_parts() -> http::request::Parts {
    http::Request::new(()).into_parts().0
}

fn new_resp_parts() -> http::response::Parts {
    http::Response::new(()).into_parts().0
}

fn decode_http1_version(v: u8) -> Result<http::Version, HTTPParseError> {
    Ok(match v {
        0 => http::Version::HTTP_10,
        1 => http::Version::HTTP_11,
        v => return Err(HTTPParseError::BadVersion(v)),
    })
}

fn content_length(hm: &HeaderMap) -> usize {
    hm.get(CONTENT_LENGTH)
        .and_then(|v| usize::from_str_radix(v.to_str().ok()?, 10).ok())
        .unwrap_or(0)
}

impl HTTP1Flow {
    fn new(request_id: RequestId) -> Self {
        Self {
            request_id,
            ..Self::default()
        }
    }

    // FIXME: a bunch of repeated code
    fn do_server_recv_headers(
        &mut self,
        data: &[u8],
        next: OnwardData<'_>,
    ) -> Result<usize, HTTPParseError> {
        let buf = &mut self.req_buf;
        let remain = &mut self.req_remain;
        let state = &mut self.server_state;
        let to_client = false;
        let encoded_length = &mut self.req_sent;

        buf.extend_from_slice(&data);

        let mut headers = Vec::new();
        headers.resize(MAX_HEADERS, httparse::EMPTY_HEADER);

        let mut request = httparse::Request::new(&mut headers);
        let body_start = request.parse(&buf);

        match body_start {
            Ok(httparse::Status::Partial) => {
                // we just need to get more data. it has been buffered, try
                // again next time
                return Ok(0);
            }
            Ok(httparse::Status::Complete(body_start)) => {
                *encoded_length += body_start;

                let mut parts = new_req_parts();
                parts.method = http::Method::from_bytes(request.method.unwrap().as_bytes())?;
                // FIXME: this URI handling sucks and we could do better: we
                // can collect SNI and Host header information and synthesize
                // the URI from at least those. h2 does it way better due to
                // the pseudos.
                parts.uri = request.path.unwrap().parse::<http::Uri>()?;
                parts.version = decode_http1_version(request.version.unwrap())?;
                parts.headers = to_header_map(&headers);
                parts.extensions = http::Extensions::new();

                let content_length = content_length(&parts.headers);
                *remain = content_length;

                next.next.on_data(
                    next.timing.clone(),
                    next.target,
                    false,
                    HTTPStreamEvent::NewRequest(self.request_id, parts),
                );

                *state = HTTP1ParserState::Body;
                let data = buf[body_start..].to_vec();
                buf.clear();
                Ok(body_start + self.stream_body(to_client, data, next))
            }
            Err(err) => {
                tracing::debug!("bad http request: {err}");
                Err(err.into())
            }
        }
    }

    fn do_client_recv_headers(
        &mut self,
        data: &[u8],
        next: OnwardData<'_>,
    ) -> Result<usize, HTTPParseError> {
        let buf = &mut self.resp_buf;
        let remain = &mut self.resp_remain;
        let state = &mut self.client_state;
        let to_client = true;
        let encoded_length = &mut self.resp_sent;

        buf.extend_from_slice(&data);

        let mut headers = Vec::new();
        headers.resize(MAX_HEADERS, httparse::EMPTY_HEADER);

        let mut response = httparse::Response::new(&mut headers);
        let body_start = response.parse(&buf);

        match body_start {
            Ok(httparse::Status::Partial) => {
                // we just need to get more data. it has been buffered, try
                // again next time
                return Ok(0);
            }
            Ok(httparse::Status::Complete(body_start)) => {
                *encoded_length += body_start;

                let mut parts = new_resp_parts();
                parts.status = http::StatusCode::from_u16(response.code.unwrap())?;
                parts.version = decode_http1_version(response.version.unwrap())?;
                parts.headers = to_header_map(&headers);
                parts.extensions = http::Extensions::new();

                let content_length = content_length(&parts.headers);
                *remain = content_length;

                next.next.on_data(
                    next.timing.clone(),
                    next.target,
                    true,
                    HTTPStreamEvent::NewResponse(self.request_id, parts),
                );

                *state = HTTP1ParserState::Body;
                let data = buf[body_start..].to_vec();
                buf.clear();
                Ok(body_start + self.stream_body(to_client, data, next))
            }
            Err(err) => Err(err.into()),
        }
    }

    fn stream_body(&mut self, to_client: bool, chunk: Vec<u8>, next: OnwardData<'_>) -> usize {
        tracing::debug!(
            "body to_client={to_client}:\n{}",
            hexdump::HexDumper::new(&chunk)
        );

        let len = chunk.len();

        let (remain, encoded_length, msg) = if to_client {
            (
                &mut self.resp_remain,
                &mut self.req_sent,
                HTTPStreamEvent::RespBodyChunk(self.request_id, chunk),
            )
        } else {
            (
                &mut self.req_remain,
                &mut self.req_sent,
                HTTPStreamEvent::ReqBodyChunk(self.request_id, chunk),
            )
        };
        let to_consume = len.min(*remain);
        *remain -= to_consume;
        *encoded_length += to_consume;

        next.next
            .on_data(next.timing.clone(), next.target, to_client, msg);

        // end of response, next request is a new one in the same
        // flow/connection
        if *remain == 0 {
            if to_client {
                next.next.on_data(
                    next.timing,
                    next.target,
                    to_client,
                    HTTPStreamEvent::ResponseFinished(self.request_id, *encoded_length),
                );
                let new = Self::new((next.new_request_id)());
                let _ = std::mem::replace(self, new);
            } else {
                next.next.on_data(
                    next.timing,
                    next.target,
                    to_client,
                    HTTPStreamEvent::RequestFinished(self.request_id, *encoded_length),
                );
            }
        }

        to_consume
    }

    fn handle_request(
        &mut self,
        timing: &TimingInfo,
        target: IPTarget,
        to_client: bool,
        next: &mut dyn Listener<HTTPStreamEvent>,
        new_request_id: &mut impl FnMut() -> RequestId,
        data: &mut Vec<u8>,
    ) {
        while data.len() > 0 {
            let onward = OnwardData {
                timing: timing.clone(),
                target,
                new_request_id,
                next,
            };

            let side_state = if to_client {
                self.client_state
            } else {
                self.server_state
            };

            let eaten = match (to_client, side_state) {
                (false, HTTP1ParserState::RecvHeaders) => {
                    match self.do_server_recv_headers(&data, onward) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(
                                "request_id={} error parsing http request: {e}",
                                self.request_id
                            );
                            self.server_state = HTTP1ParserState::Error;
                            0
                        }
                    }
                }
                (false, HTTP1ParserState::Body) => {
                    self.stream_body(to_client, data.clone(), onward)
                }
                (true, HTTP1ParserState::RecvHeaders) => {
                    match self.do_client_recv_headers(&data, onward) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(
                                "request_id={} error parsing http response: {e}",
                                self.request_id
                            );
                            self.client_state = HTTP1ParserState::Error;
                            0
                        }
                    }
                }
                (true, HTTP1ParserState::Body) => self.stream_body(to_client, data.clone(), onward),
                (_, HTTP1ParserState::Error) => return,
            };

            *data = data[eaten..].to_vec();
        }
    }
}

enum HTTPFlow {
    HTTP1Flow(HTTP1Flow),
    HTTP2Flow(HTTP2Flow),
}

impl HTTPFlow {
    fn request_id(&self) -> RequestId {
        match self {
            HTTPFlow::HTTP1Flow(f) => f.request_id,
            HTTPFlow::HTTP2Flow(f) => f.request_id,
        }
    }
}

pub struct HTTPRequestTracker {
    request_id: RequestId,
    flows: HashMap<IPTarget, HTTPFlow>,
    next: Box<dyn Listener<HTTPStreamEvent>>,
}

impl HTTPRequestTracker {
    pub fn new(next: Box<dyn Listener<HTTPStreamEvent>>) -> Self {
        HTTPRequestTracker {
            request_id: 0,
            flows: Default::default(),
            next,
        }
    }
}

impl Listener<Vec<u8>> for HTTPRequestTracker {
    fn on_data(
        &mut self,
        timing: TimingInfo,
        target: crate::chomp::IPTarget,
        to_client: bool,
        mut data: Vec<u8>,
    ) {
        let mut new_request_id = || {
            let i = self.request_id;
            self.request_id += 1;
            i
        };

        let entry = self.flows.entry(target).or_insert_with(|| {
            HTTPFlow::HTTP1Flow(HTTP1Flow {
                request_id: new_request_id(),
                ..Default::default()
            })
        });
        // tracing::debug!(
        //     "data to_client={to_client}:\n{}",
        //     hexdump::HexDumper::new(&data)
        // );
        let s = tracing::span!(
            tracing::Level::DEBUG,
            "http",
            version = tracing::field::Empty,
            request_id = entry.request_id(),
            ?to_client,
        )
        .entered();

        match entry {
            HTTPFlow::HTTP1Flow(entry) => {
                s.record("version", "h1");
                tracing::debug!(?entry.client_state, ?entry.server_state, "h1 state");
                entry.handle_request(
                    &timing,
                    target,
                    to_client,
                    &mut *self.next,
                    &mut new_request_id,
                    &mut data,
                )
            }

            HTTPFlow::HTTP2Flow(entry) => {
                let onward = OnwardData {
                    timing: timing.clone(),
                    target,
                    new_request_id: &mut new_request_id,
                    next: &mut *self.next,
                };

                s.record("version", "h2");
                match entry.handle_request(to_client, &mut data, onward) {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!("error in h2 handling: {e}");
                    }
                }
            }
        }
    }

    fn on_side_data(&mut self, data: Box<dyn SideData>) {
        let mut new_request_id = || {
            let i = self.request_id;
            self.request_id += 1;
            i
        };

        if let Some(alpn) = (&*data)
            .as_any()
            .downcast_ref::<tls::side_data::ALPNCompleted>()
        {
            tracing::debug!(?alpn, "ALPN");

            if alpn.protocols.iter().any(|e| e.0 == b"h2") {
                let _ = self.flows.entry(alpn.target).or_insert_with(|| {
                    HTTPFlow::HTTP2Flow(HTTP2Flow {
                        request_id: new_request_id(),
                        ..Default::default()
                    })
                });
            }
        }
        self.next.on_side_data(data);
    }
}

#[cfg(test)]
mod test {
    use std::{
        io::Cursor,
        sync::{Arc, RwLock},
    };

    use crate::{chomp::dump_pcap, key_db::KeyDB, test_support::*};

    use super::HTTPStreamEvent;

    fn http_test(f: &[u8]) -> Vec<Received<HTTPStreamEvent>> {
        let mut reader = Cursor::new(f);
        let key_db: Arc<RwLock<KeyDB>> = Default::default();
        let received = Arc::new(RwLock::new(Vec::new()));
        let mut chomper = http_chomper(key_db, received.clone());

        dump_pcap(&mut reader, &mut chomper).unwrap();
        let mut lock = received.write().unwrap();
        std::mem::take(&mut *lock)
    }

    #[test]
    fn test_h1_simple() {
        check(
            expect_test::expect_file!("./test_output/http/h1_simple"),
            &http_test(NYA_DSB),
        )
    }

    #[test]
    fn test_h1_conn_reuse() {
        check(
            expect_test::expect_file!("./test_output/http/h1_conn_reuse"),
            &http_test(H1_CONN_REUSE),
        )
    }

    #[test]
    fn test_h2() {
        check(
            expect_test::expect_file!("./test_output/http/h2"),
            &http_test(H2),
        )
    }

    #[test]
    fn test_h2_header_continuation() {
        // FIXME: there is another bug revealed here: we are not doing gzip
        // compression properly.
        check(
            expect_test::expect_file!("./test_output/http/h2_header_continuation"),
            &http_test(H2_BIG_HEADERS),
        )
    }

    #[test]
    fn test_h1_unencrypted() {
        check(
            expect_test::expect_file!("./test_output/http/h1_unencrypted"),
            &http_test(H1_UNENCRYPTED),
        )
    }
}
