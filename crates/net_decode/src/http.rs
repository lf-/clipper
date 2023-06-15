//! HTTP decoding using h2 and httparse
//!
//! FIXME:
//! - How do we do streaming properly?
//! - How do we do connection reuse properly? We should transition out of Body
//!   to RecvHeaders, probably, and clear the request?

use std::collections::HashMap;

use http::{HeaderMap, HeaderName, HeaderValue};

use crate::{chomp::IPTarget, tcp_reassemble::TCPFlowReceiver};

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

#[derive(Default)]
pub struct HTTP1Flow {
    client_state: HTTP1ParserState,
    server_state: HTTP1ParserState,
    // FIXME: technically with malicious input this could waste unbounded
    // memory. maybe we should give up after a while?
    // FIXME: streaming misery
    req: http::Request<Vec<u8>>,
    resp: http::Response<Vec<u8>>,
}

fn handle_http_parse_result(
    body_start: httparse::Result<usize>,
    headers: &[httparse::Header<'_>],
    header_map: &mut HeaderMap,
    state: &mut HTTP1ParserState,
) -> Result<usize, ()> {
    match body_start {
        Ok(httparse::Status::Partial) => {
            // we just need to get more data. it has been buffered, try
            // again next time
            Err(())
        }
        Ok(httparse::Status::Complete(body_start)) => {
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
            *state = HTTP1ParserState::Body;
            Ok(body_start)
        }
        Err(err) => {
            tracing::debug!("bad http request: {err}");
            *state = HTTP1ParserState::Error;
            Err(())
        }
    }
}

impl HTTP1Flow {
    fn do_server_recv_headers(&mut self, data: Vec<u8>) {
        let mut buf = Vec::new();
        std::mem::swap(&mut buf, self.req.body_mut());
        buf.extend_from_slice(&data);

        let mut headers = Vec::new();
        headers.resize(MAX_HEADERS, httparse::EMPTY_HEADER);

        let body_start = {
            let mut request = httparse::Request::new(&mut headers);
            request.parse(&buf)
        };

        let r = handle_http_parse_result(
            body_start,
            &headers,
            &mut self.req.headers_mut(),
            &mut self.server_state,
        );

        std::mem::swap(&mut buf, self.req.body_mut());
        match r {
            Ok(body_start) => {
                let b = self.req.body_mut();
                *b = b[body_start..].to_vec();
                self.stream_body(false)
            }
            Err(()) => {}
        }
    }

    fn do_client_recv_headers(&mut self, data: Vec<u8>) {
        let mut buf = Vec::new();
        std::mem::swap(&mut buf, self.resp.body_mut());
        buf.extend_from_slice(&data);

        let mut headers = Vec::new();
        headers.resize(MAX_HEADERS, httparse::EMPTY_HEADER);

        let body_start = {
            let mut response = httparse::Response::new(&mut headers);
            response.parse(&buf)
        };

        let r = handle_http_parse_result(
            body_start,
            &headers,
            &mut self.resp.headers_mut(),
            &mut self.client_state,
        );

        std::mem::swap(&mut buf, self.resp.body_mut());
        match r {
            Ok(body_start) => {
                let b = self.resp.body_mut();
                *b = b[body_start..].to_vec();
                self.stream_body(true)
            }
            Err(()) => {}
        }
    }

    fn stream_body(&mut self, to_client: bool) {
        let buf = if to_client {
            self.resp.body_mut()
        } else {
            self.req.body_mut()
        };

        tracing::debug!(
            "body to_client={to_client}:\n{}",
            hexdump::HexDumper::new(&buf)
        );

        let headers = if to_client {
            self.resp.headers()
        } else {
            self.req.headers()
        };
        tracing::debug!("headers to_client={to_client}\n{:?}", headers);
    }
}

#[derive(Default)]
pub struct HTTPRequestTracker {
    flows: HashMap<IPTarget, HTTP1Flow>,
}

impl TCPFlowReceiver for HTTPRequestTracker {
    fn on_data(&mut self, target: crate::chomp::IPTarget, to_client: bool, data: Vec<u8>) {
        let entry = self.flows.entry(target).or_insert_with(Default::default);
        // tracing::debug!(
        //     "data to_client={to_client}:\n{}",
        //     hexdump::HexDumper::new(&data)
        // );

        tracing::debug!(?entry.client_state, ?entry.server_state);
        let side_state = if to_client {
            entry.client_state
        } else {
            entry.server_state
        };

        match (to_client, side_state) {
            (false, HTTP1ParserState::RecvHeaders) => entry.do_server_recv_headers(data),
            (false, HTTP1ParserState::Body) => {
                entry.req.body_mut().extend_from_slice(&data);
                entry.stream_body(to_client);
            }
            (true, HTTP1ParserState::RecvHeaders) => entry.do_client_recv_headers(data),
            (true, HTTP1ParserState::Body) => {
                entry.resp.body_mut().extend_from_slice(&data);
                entry.stream_body(to_client);
            }
            (_, HTTP1ParserState::Error) => return,
        }
    }
}
