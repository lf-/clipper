// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Uses RPC to send the keys to the parent clipper instance.

use std::{path::PathBuf, sync::OnceLock};

use clipper_protocol::proto::embedding::{
    clipper_embedding_client::ClipperEmbeddingClient, new_keys_req::Keys, NewKeysReq, TlsKeys,
};
use tokio::{
    net::UnixStream,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tokio_util::sync::CancellationToken;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

use crate::log_target::TLSKeyLogLine;

static EXIT_GUARD: OnceLock<CancellationToken> = OnceLock::new();

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

impl From<TLSKeyLogLine> for TlsKeys {
    fn from(value: TLSKeyLogLine) -> Self {
        Self {
            label: value.label,
            client_random: value.client_random,
            secret: value.secret,
        }
    }
}

#[ctor::dtor]
fn shutdown() {
    if let Some(g) = EXIT_GUARD.get() {
        g.cancel();
    }
}

async fn go(mut recv: UnboundedReceiver<TLSKeyLogLine>, sock_addr: PathBuf) -> Result<(), Error> {
    // for unknown reasons, the service_fn thing below is FnMut so it cannot
    // have stuff moved into it.
    let sock_addr = Box::leak(sock_addr.into_boxed_path());

    let endpoint = Endpoint::try_from("http://[::]:1337")?
        .connect_with_connector(service_fn(|_: Uri| UnixStream::connect(&*sock_addr)))
        .await?;

    let mut client = ClipperEmbeddingClient::new(endpoint);
    let tok = EXIT_GUARD.get().unwrap().clone();

    loop {
        tokio::select! {
            msg = recv.recv() => {
                match msg {
                    Some(msg) => {
                        tracing::debug!("msg: {msg:?}");
                        let req = tonic::Request::new(NewKeysReq {
                            keys: Some(Keys::TlsKeys(msg.into())),
                        });

                        client.new_keys(req).await?;
                    }
                    None => break Ok(()),
                }
            }
            _cancel = tok.cancelled() => {
                tracing::debug!("shutdown");
                break Ok(())
            }
        }
    }
}

pub fn start(sock_addr: PathBuf) -> UnboundedSender<TLSKeyLogLine> {
    let (send, recv) = mpsc::unbounded_channel();
    EXIT_GUARD.set(CancellationToken::new()).unwrap();

    // FIXME: probably should do something with this join handle to stop it
    // gracefully on process exit
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio rt");

        rt.block_on(async move {
            let span = tracing::span!(tracing::Level::INFO, "sender");
            let _span_guard = span.enter();

            match go(recv, sock_addr).await {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("error in sender: {e}");
                }
            }
        })
    });

    send
}
