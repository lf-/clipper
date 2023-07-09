// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Implementation of (unprivileged) capture on Linux.
//!
//! FIXME: how do we do other-OS or privileged capture?

use clipper_protocol::proto::embedding::{
    clipper_embedding_server::{ClipperEmbedding, ClipperEmbeddingServer},
    new_keys_req::Keys,
    NewKeysReq, NewKeysResp, TlsKeys,
};
use futures::{Future, StreamExt};
use net_decode::{
    chomp::{EthernetChomper, FrameChomper},
    key_db::{ClientRandom, KeyDB, Secret, SecretType},
    listener::TimingInfo,
    tls::TLSFlowTracker,
};
use tokio::{
    fs::OpenOptions as TokioOpenOptions,
    io::{unix::AsyncFd, AsyncSeekExt, AsyncWriteExt},
};
use tokio_util::sync::CancellationToken;
use tonic::Response;
use wire_blahaj::{
    pcap_writer::{AsyncWriteHack, PcapWriter},
    unprivileged::{run_in_ns, CapturedPacketMeta, LaunchHooks},
};

use std::{
    fs::read_link,
    future,
    os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::net::UnixListener,
    },
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, RwLock},
};

use crate::{
    chomper,
    devtools::{make_devtools_listener, run_devtools_server, DevtoolsListener},
    Error,
};

struct EmbeddingServer {
    send: tokio::sync::mpsc::Sender<(ClientRandom, SecretType, Secret)>,
}

#[tonic::async_trait]
impl ClipperEmbedding for EmbeddingServer {
    async fn new_keys(
        &self,
        request: tonic::Request<NewKeysReq>,
    ) -> Result<tonic::Response<NewKeysResp>, tonic::Status> {
        tracing::debug!("embedding server got keys: {:?}", &request);

        let request = request.into_inner();
        match request.keys {
            Some(Keys::TlsKeys(TlsKeys {
                label,
                client_random,
                secret,
            })) => self
                .send
                .send((
                    ClientRandom(client_random),
                    label
                        .as_bytes()
                        .try_into()
                        .map_err(|_| tonic::Status::invalid_argument("bad secret type"))?,
                    Secret(secret),
                ))
                .await
                .map_err(|_| tonic::Status::internal("closed channel?"))?,
            None => {}
        }

        Ok(Response::new(NewKeysResp {
            ok: true,
            ..Default::default()
        }))
    }
}

#[async_trait::async_trait]
pub trait CaptureTarget {
    async fn on_packet(
        &mut self,
        key_db: Arc<RwLock<KeyDB>>,
        meta: CapturedPacketMeta,
        packet: Vec<u8>,
    ) -> Result<(), Error>;

    async fn shutdown(self, key_db: Arc<RwLock<KeyDB>>) -> Result<(), Error>;

    /// Called after the key has been added to the key db already.
    async fn on_key(
        &mut self,
        _key_db: Arc<RwLock<KeyDB>>,
        _client_random: ClientRandom,
        _secret_type: SecretType,
        _secret: Secret,
    ) -> Result<(), Error>;
}

pub struct CaptureToPcap {
    file: tokio::fs::File,
    packets_writer: tokio::io::BufWriter<tokio::fs::File>,
    writer: AsyncWriteHack,
    pcap_writer: PcapWriter,
}

impl CaptureToPcap {
    pub async fn new(output_file: &Path) -> Result<Self, Error> {
        let mut file = TokioOpenOptions::new()
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
        let packets_file = tokio::fs::File::from_std(tempfile::tempfile()?);
        let packets_writer = tokio::io::BufWriter::new(packets_file);

        let mut writer = AsyncWriteHack::default();
        let pcap_writer = PcapWriter::new(crate::APP_IDENTIFICATION, &mut writer)?;
        writer.flush_downstream(&mut file).await?;

        Ok(Self {
            file,
            pcap_writer,
            writer,
            packets_writer,
        })
    }
}

#[async_trait::async_trait]
impl CaptureTarget for CaptureToPcap {
    async fn on_packet(
        &mut self,
        _key_db: Arc<RwLock<KeyDB>>,
        meta: CapturedPacketMeta,
        packet: Vec<u8>,
    ) -> Result<(), Error> {
        self.pcap_writer.on_packet(
            &mut self.writer,
            wire_blahaj::ts_to_nanos(meta.time),
            meta.if_index as u32,
            &packet,
        )?;
        self.writer
            .flush_downstream(&mut self.packets_writer)
            .await?;

        tracing::trace!("pakit {} {}", meta.time, hexdump::HexDumper::new(&packet));
        Ok(())
    }

    async fn shutdown(mut self, key_db: Arc<RwLock<KeyDB>>) -> Result<(), Error> {
        self.packets_writer.flush().await?;

        self.pcap_writer
            .on_dsb(&mut self.writer, &key_db.read().unwrap().to_key_log())?;
        self.writer.flush_downstream(&mut self.file).await?;

        let mut packets_file = self.packets_writer.into_inner();

        packets_file.seek(std::io::SeekFrom::Start(0)).await?;
        tokio::io::copy(&mut packets_file, &mut self.file).await?;
        Ok(())
    }

    async fn on_key(
        &mut self,
        _key_db: Arc<RwLock<KeyDB>>,
        _client_random: ClientRandom,
        _secret_type: SecretType,
        _secret: Secret,
    ) -> Result<(), Error> {
        Ok(())
    }
}

pub struct CaptureToDevtools {
    devtools_listener: Option<DevtoolsListener>,
    chomper: Option<EthernetChomper<TLSFlowTracker>>,
    join: tokio::task::JoinHandle<Result<(), Error>>,
}

impl CaptureToDevtools {
    async fn new(terminate: CancellationToken) -> Self {
        let (devtools_listener, bits) = make_devtools_listener();

        let join = tokio::spawn(async move { run_devtools_server(bits, terminate).await });

        Self {
            join,
            chomper: None,
            devtools_listener: Some(devtools_listener),
        }
    }

    fn init(&mut self, key_db: Arc<RwLock<KeyDB>>) {
        if self.chomper.is_none() {
            self.chomper = Some(chomper(
                Box::new(self.devtools_listener.take().unwrap()),
                key_db,
            ));
        }
    }
}

#[async_trait::async_trait]
impl CaptureTarget for CaptureToDevtools {
    async fn on_packet(
        &mut self,
        key_db: Arc<RwLock<KeyDB>>,
        meta: CapturedPacketMeta,
        packet: Vec<u8>,
    ) -> Result<(), Error> {
        self.init(key_db);
        self.chomper.as_mut().unwrap().chomp(
            TimingInfo {
                received_on_wire: wire_blahaj::ts_to_nanos(meta.time),
                other_times: Default::default(),
            },
            &packet,
        )
    }

    async fn shutdown(mut self, _key_db: Arc<RwLock<KeyDB>>) -> Result<(), Error> {
        self.join.await??;
        Ok(())
    }

    async fn on_key(
        &mut self,
        key_db: Arc<RwLock<KeyDB>>,
        client_random: ClientRandom,
        secret_type: SecretType,
        secret: Secret,
    ) -> Result<(), Error> {
        self.init(key_db);
        self.chomper
            .as_mut()
            .unwrap()
            .on_key(client_random, secret_type, secret);
        Ok(())
    }
}

async fn start_capture(
    mut target: (impl CaptureTarget + Unpin),
    listener: UnixListener,
    raw_fd: RawFd,
    terminate: CancellationToken,
) -> Result<(), Error> {
    let mut cap = unsafe { wire_blahaj::unprivileged::UnprivilegedCapture::new(raw_fd)? }.fuse();

    let key_db: Arc<RwLock<KeyDB>> = Default::default();

    let listener = tokio::net::UnixListener::from_std(listener)?;
    let listener_stream = tokio_stream::wrappers::UnixListenerStream::new(listener);
    let (send, mut recv_keys) = tokio::sync::mpsc::channel(1000);
    let embedding_server = EmbeddingServer { send };

    let mut server_join = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(ClipperEmbeddingServer::new(embedding_server))
            .serve_with_incoming(listener_stream),
    );

    loop {
        tokio::select! {
            v = cap.select_next_some() => {
                let (v, meta) = v?;

                target.on_packet(key_db.clone(), meta, v).await?;
            }
            Some((cr, ty, secret)) = recv_keys.recv() => {
                key_db.write().unwrap().on_secret(cr.clone(), ty, secret.clone());
                target.on_key(key_db.clone(), cr, ty, secret).await?;
            }
            _ = terminate.cancelled() => {
                target.shutdown(key_db.clone()).await?;

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

type MakeCapture<T> =
    Box<dyn FnOnce(CancellationToken) -> Pin<Box<dyn Future<Output = Result<T, Error>>>>>;

struct ClipperLaunchHooks<T: CaptureTarget> {
    make_capture: MakeCapture<T>,
    unix_sock_dir: PathBuf,
    unix_listener: Option<UnixListener>,
}

impl<T: CaptureTarget> ClipperLaunchHooks<T> {
    fn sock(&self) -> PathBuf {
        self.unix_sock_dir.join(SOCK_NAME)
    }
}

impl<T: CaptureTarget + Unpin + 'static> LaunchHooks for ClipperLaunchHooks<T> {
    fn parent_after_fork(&mut self) {
        let listener = UnixListener::bind(self.sock()).expect("bind unix sock");
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

            let make_capture = std::mem::replace(
                &mut self.make_capture,
                Box::new(|_| Box::pin(future::pending())),
            );

            start_capture(
                make_capture(cancel.clone()).await?,
                listener,
                capture_fd,
                cancel,
            )
            .await
        }) {
            Ok(_) => {}
            Err(e) => tracing::error!("Error capturing: {e}"),
        }
    }

    fn add_env(&self) -> Vec<(String, String)> {
        let mut vars = vec![(
            clipper_protocol::SOCKET_ENV_VAR.to_string(),
            self.sock().to_str().unwrap().to_string(),
        )];

        // FIXME: this will be very broken for packaging
        let clipper_inject_so = read_link("/proc/self/exe")
            .ok()
            .and_then(|l| Some(l.parent()?.join("libclipper_inject.so")));
        if let Some(so) = clipper_inject_so {
            if so.exists() {
                vars.push(("LD_PRELOAD".to_string(), so.to_str().unwrap().to_string()))
            }
        }

        vars
    }
}

pub fn do_capture_to_pcap(file: PathBuf, args: Vec<String>) -> Result<(), Error> {
    do_capture(
        Box::new(move |_| Box::pin(async move { CaptureToPcap::new(&file).await })),
        args,
    )
}

pub fn do_capture<T: CaptureTarget + Unpin + 'static>(
    make_capture: MakeCapture<T>,
    args: Vec<String>,
) -> Result<(), Error> {
    let temp_dir = tempfile::tempdir()?;
    let mut hooks = ClipperLaunchHooks {
        make_capture,
        unix_sock_dir: temp_dir.into_path(),
        unix_listener: None,
    };

    unsafe { run_in_ns(args, &mut hooks)? };
    Ok(())
}

pub fn do_capture_to_devtools(args: Vec<String>) -> Result<(), Error> {
    do_capture(
        Box::new(move |cancel| Box::pin(async move { Ok(CaptureToDevtools::new(cancel).await) })),
        args,
    )
}
