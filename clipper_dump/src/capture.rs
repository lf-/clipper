// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Implementation of (unprivileged) capture on Linux.
//!
//! FIXME: how do we do other-OS or privileged capture?

use clipper_protocol::proto::embedding::{
    clipper_embedding_server::{ClipperEmbedding, ClipperEmbeddingServer},
    NewKeysReq, NewKeysResp,
};
use futures::StreamExt;
use tokio::{
    fs::OpenOptions as TokioOpenOptions,
    io::{unix::AsyncFd, AsyncSeekExt, AsyncWriteExt},
};
use tokio_util::sync::CancellationToken;
use tonic::Response;
use wire_blahaj::{
    pcap_writer::{AsyncWriteHack, PcapWriter},
    unprivileged::{run_in_ns, LaunchHooks},
};

use std::{
    os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::net::UnixListener,
    },
    path::{Path, PathBuf},
};

use crate::Error;

struct EmbeddingServer {}

#[tonic::async_trait]
impl ClipperEmbedding for EmbeddingServer {
    async fn new_keys(
        &self,
        request: tonic::Request<NewKeysReq>,
    ) -> Result<tonic::Response<NewKeysResp>, tonic::Status> {
        tracing::debug!("embedding server got keys: {:?}", &request);

        Ok(Response::new(NewKeysResp {
            ok: true,
            ..Default::default()
        }))
    }
}

async fn start_capture(
    output_file: &Path,
    listener: UnixListener,
    raw_fd: RawFd,
    terminate: CancellationToken,
) -> Result<(), Error> {
    let mut cap = unsafe { wire_blahaj::unprivileged::UnprivilegedCapture::new(raw_fd)? }.fuse();
    let async_writer = TokioOpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(output_file)
        .await?;

    // XXX: to comply with the pcapng standard, which states that DSB entries
    // SHOULD be before the affected packets, we need to put the packets
    // somewhere. WELL, since you can just concatenate pcapng stuff together,
    // let's just write the packets into a tempfile and on exit copy it back
    // into the main file. Horrible but *so* funny.
    let mut packets_file = tokio::fs::File::from_std(tempfile::tempfile()?);
    let packets_writer = tokio::io::BufWriter::new(&mut packets_file);

    tokio::pin!(async_writer);
    tokio::pin!(packets_writer);

    let mut writer = AsyncWriteHack::default();
    let mut pcap_writer = PcapWriter::new(&mut writer)?;
    writer.flush_downstream(&mut async_writer).await?;

    let listener = tokio::net::UnixListener::from_std(listener)?;
    let listener_stream = tokio_stream::wrappers::UnixListenerStream::new(listener);
    let embedding_server = EmbeddingServer {};

    let mut server_join = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(ClipperEmbeddingServer::new(embedding_server))
            .serve_with_incoming(listener_stream),
    );

    loop {
        tokio::select! {
            v = cap.select_next_some() => {
                let (v, meta) = v?;

                pcap_writer.on_packet(
                    &mut writer,
                    wire_blahaj::ts_to_nanos(meta.time),
                    meta.if_index as u32,
                    &v,
                )?;
                writer.flush_downstream(&mut packets_writer).await?;

                tracing::debug!("pakit {} {}", meta.time, hexdump::HexDumper::new(&v));
                // pcap_writer.on_packet(ts);
            }
            _ = terminate.cancelled() => {
                packets_writer.flush().await?;
                drop(packets_writer);

                packets_file.seek(std::io::SeekFrom::Start(0)).await?;
                tokio::io::copy(&mut packets_file, &mut async_writer).await?;

                break Ok(());
            }
            e = &mut server_join => {
                match e {
                    Ok(inner) => break inner.map_err(|e| e.into()),
                    Err(inner) => break Err(inner.into())
                }
            }
        };
    }
}

const SOCK_NAME: &'static str = "clipper.sock";

struct ClipperLaunchHooks {
    output_file: PathBuf,
    unix_sock_dir: PathBuf,
    unix_listener: Option<UnixListener>,
}

impl LaunchHooks for ClipperLaunchHooks {
    fn parent_after_fork(&mut self) {
        let listener =
            UnixListener::bind(self.unix_sock_dir.join(SOCK_NAME)).expect("bind unix sock");
        listener.set_nonblocking(true).expect("set nonblocking");
        self.unix_listener = Some(listener);
    }

    fn parent_go(&mut self, child_pidfd: RawFd, capture_fd: RawFd) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let unix_sock_dir = self.unix_sock_dir.clone();
        let listener = self.unix_listener.take().unwrap();

        match rt.block_on(async move {
            let cancel = CancellationToken::new();
            let child_pidfd = AsyncFd::new(unsafe { OwnedFd::from_raw_fd(child_pidfd) })?;

            let _join_handle = tokio::spawn({
                let cancel = cancel.clone();
                async move {
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                let _ = tokio::fs::remove_dir_all(&unix_sock_dir).await;
                                break;
                            }
                            _ = tokio::signal::ctrl_c() => {
                                cancel.cancel();
                            }
                            _g = child_pidfd.readable() => {
                                cancel.cancel();
                            }
                        };
                    }
                }
            });

            start_capture(&self.output_file, listener, capture_fd, cancel).await
        }) {
            Ok(_) => {}
            Err(e) => tracing::error!("Error capturing: {e}"),
        }
    }
}

pub fn do_capture(output_file: PathBuf, args: Vec<String>) -> Result<(), Error> {
    let temp_dir = tempfile::tempdir()?;
    let mut hooks = ClipperLaunchHooks {
        output_file,
        unix_sock_dir: temp_dir.into_path(),
        unix_listener: None,
    };

    unsafe { run_in_ns(args, &mut hooks)? };
    Ok(())
}
