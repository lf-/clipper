// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! HTTP decoding using h2 and httparse
//!
//! FIXME:
//! - Gzip

use std::{collections::HashMap, fmt};

use http::{header::CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue};

use crate::{
    chomp::IPTarget,
    listener::{Listener, SideData, TimingInfo},
};

pub type RequestId = u64;

pub enum HTTPStreamEvent {
    NewRequest(RequestId, http::request::Parts),
    ReqBodyChunk(RequestId, Vec<u8>),
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
        if *remain == 0 && to_client {
            next.next.on_data(
                next.timing,
                next.target,
                to_client,
                HTTPStreamEvent::ResponseFinished(self.request_id, *encoded_length),
            );
            let new = Self::new((next.new_request_id)());
            let _ = std::mem::replace(self, new);
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

        match entry {
            HTTPFlow::HTTP1Flow(entry) => {
                tracing::debug!(?entry.client_state, ?entry.server_state);
                entry.handle_request(
                    &timing,
                    target,
                    to_client,
                    &mut *self.next,
                    &mut new_request_id,
                    &mut data,
                )
            }
        }
    }

    fn on_side_data(&mut self, data: Box<dyn SideData>) {
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
}
