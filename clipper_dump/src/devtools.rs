//! Chrome Devtools Protocol implementation, application code

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use devtools_server::{
    cdp::cdp::browser_protocol::network::{self, EventRequestWillBeSent},
    cdp_types::{self, CdpJsonEventMessage, MethodCall},
    ConnectionStream,
};
use futures::{Stream, StreamExt};
use http::HeaderMap;
use net_decode::{chomp, http::HTTPStreamEvent, key_db::KeyDB, listener::Listener};
use tokio::sync::broadcast;

use crate::{chomper, Error};

#[derive(Debug)]
pub enum DevtoolsProtoEvent {
    HTTPStreamEvent(HTTPStreamEvent),
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

fn to_cdp_event_message(
    ev: impl cdp_types::Method + serde::ser::Serialize,
) -> Result<cdp_types::Message, Error> {
    Ok(cdp_types::Message::Event(CdpJsonEventMessage {
        method: ev.identifier(),
        session_id: None,
        params: serde_json::to_value(ev)?,
    }))
}

#[derive(Default)]
struct ClientState {
    network_enabled: bool,
}

impl ClientState {
    async fn handle_conn(
        &mut self,
        mut conn: devtools_server::ServerConnection,
        recv: impl Stream<Item = Arc<DevtoolsProtoEvent>>,
    ) -> Result<(), devtools_server::Error> {
        tokio::pin!(recv);
        loop {
            tokio::select! {
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

        match msg {
            DevtoolsProtoEvent::HTTPStreamEvent(hse) => match hse {
                HTTPStreamEvent::NewRequest(id, parts) => {
                    let wall_time = chrono::Utc::now().timestamp_millis() as f64 / 1000.;

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
                            post_data: None,
                            has_post_data: None,
                            post_data_entries: None,
                            mixed_content_type: None,
                            initial_priority: network::ResourcePriority::Medium,
                            referrer_policy: network::RequestReferrerPolicy::Origin,
                            is_link_preload: None,
                            trust_token_params: None,
                            is_same_site: None,
                        },
                        // TODO: time info
                        timestamp: network::MonotonicTime::new(0.),
                        wall_time: network::TimeSinceEpoch::new(wall_time),
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

                    conn.send(to_cdp_event_message(ev)?).await?;
                }
                _ => {}
            },
        }
        Ok(())
    }
}

struct DevtoolsListener {
    send: Arc<EventBuffer<DevtoolsProtoEvent>>,
}

impl Listener<HTTPStreamEvent> for DevtoolsListener {
    fn on_data(
        &mut self,
        _target: net_decode::chomp::IPTarget,
        _to_client: bool,
        data: HTTPStreamEvent,
    ) {
        self.send.send(DevtoolsProtoEvent::HTTPStreamEvent(data));
    }
}

pub async fn do_devtools_server_inner(file: PathBuf) -> Result<(), devtools_server::Error> {
    let mut conns = ConnectionStream::new("127.0.0.1:1337".parse().unwrap()).await?;

    let event_buffer = Arc::new(EventBuffer::new(100, 1000));
    let devtools_listener = DevtoolsListener {
        send: event_buffer.clone(),
    };

    let key_db = Arc::new(RwLock::new(KeyDB::default()));
    let mut chomper = chomper(Box::new(devtools_listener), key_db.clone());

    chomp::dump_pcap(file, &mut chomper, key_db)?;

    while let Some(conn) = conns.next().await {
        let conn = conn?;
        let recv = event_buffer.receiver();
        let mut client_state = ClientState::default();

        tokio::spawn(async move {
            match client_state.handle_conn(conn, recv).await {
                Ok(()) => {}
                Err(e) => tracing::error!("error in websocket connection: {e}"),
            }
        });
    }

    Ok(())
}
