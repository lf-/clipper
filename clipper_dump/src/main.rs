// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Command-line debugging tool for clipper to exercise pcap and network
//! protocol functionality before the rest of the system is built.
use clap::Parser;
use devtools::do_devtools_server_inner;
use futures::StreamExt;
use tokio::{fs::OpenOptions as TokioOpenOptions, io::AsyncWriteExt};
use wire_blahaj::{
    pcap_writer::{AsyncWriteHack, PcapWriter},
    unprivileged::run_in_ns,
};

use std::{
    fmt::Debug,
    os::fd::RawFd,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use net_decode::{
    chomp::{self, PacketChomper},
    http::{HTTPRequestTracker, HTTPStreamEvent},
    key_db::KeyDB,
    listener::{DebugListener, Listener},
    tcp_reassemble::TcpFollower,
    tls::TLSFlowTracker,
};
use tracing_subscriber::prelude::*;

mod devtools;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(clap::Parser, Debug)]
enum Command {
    DumpPcap {
        file: PathBuf,
    },
    DevtoolsServer {
        file: PathBuf,
    },
    /// Invokes a program with capture. Does not require root on Linux.
    Capture {
        /// File to write a pcapng to.
        #[clap(short = 'o', long)]
        output_file: PathBuf,
        /// Arguments for the program to invoke.
        #[clap(num_args = 0..)]
        args: Vec<String>,
    },
    /// Grabs a TAP device from the specified pid and yeets it over a Unix
    /// socket. This subcommand is used for reexecing ourselves and is of
    /// limited utility to users.
    #[cfg(target_os = "linux")]
    #[clap(hide = true)]
    GrabTap {
        pid: u64,
        dev_name: String,
        sock_fdnum: RawFd,
    },
}

pub fn chomper(
    http_listener: Box<dyn Listener<HTTPStreamEvent>>,
    key_db: Arc<RwLock<KeyDB>>,
) -> PacketChomper<TLSFlowTracker> {
    PacketChomper {
        tcp_follower: TcpFollower::default(),
        recv: TLSFlowTracker::new(key_db, Box::new(HTTPRequestTracker::new(http_listener))),
    }
}

fn do_dump_pcap(file: PathBuf) -> Result<(), Error> {
    let key_db = Arc::new(RwLock::new(KeyDB::default()));
    let mut chomper = chomper(Box::new(DebugListener {}), key_db.clone());

    chomp::dump_pcap(file, &mut chomper, key_db)?;
    Ok(())
}

fn do_devtools_server(file: PathBuf) -> Result<(), Error> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(do_devtools_server_inner(file))
}

async fn start_capture(output_file: PathBuf, raw_fd: RawFd) -> Result<(), Error> {
    let mut cap = unsafe { wire_blahaj::unprivileged::UnprivilegedCapture::new(raw_fd)? };
    let async_writer = TokioOpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(output_file)
        .await?;
    tokio::pin!(async_writer);

    let writer = AsyncWriteHack::default();
    let mut pcap_writer = PcapWriter::new(writer)?;
    pcap_writer
        .get_mut()
        .flush_downstream(&mut async_writer)
        .await?;

    while let Some(v) = cap.next().await {
        let (v, meta) = v?;

        pcap_writer.on_packet(
            wire_blahaj::ts_to_nanos(meta.time),
            meta.if_index as u32,
            &v,
        )?;
        pcap_writer
            .get_mut()
            .flush_downstream(&mut async_writer)
            .await?;
        async_writer.flush().await?;

        tracing::debug!("pakit {} {}", meta.time, hexdump::HexDumper::new(&v));
        // pcap_writer.on_packet(ts);
    }
    Ok(())
}

fn do_capture(output_file: PathBuf, args: Vec<String>) -> Result<(), Error> {
    unsafe {
        run_in_ns(args, |fd| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            match rt.block_on(start_capture(output_file, fd)) {
                Ok(_) => {}
                Err(e) => tracing::error!("Error capturing: {e}"),
            }
        })?
    };
    Ok(())
}

fn main() -> Result<(), Error> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::Layer::new().without_time())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Command::parse();

    match args {
        Command::DumpPcap { file } => do_dump_pcap(file)?,
        Command::DevtoolsServer { file } => do_devtools_server(file)?,
        Command::Capture { args, output_file } => do_capture(output_file, args)?,
        #[cfg(target_os = "linux")]
        Command::GrabTap {
            pid,
            dev_name,
            sock_fdnum,
        } => unsafe {
            wire_blahaj::unprivileged::send_capture_socket_for_ns(pid, &dev_name, sock_fdnum)?
        },
    }
    Ok(())
}
