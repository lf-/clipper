// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Command-line debugging tool for clipper to exercise pcap and network
//! protocol functionality before the rest of the system is built.
use clap::Parser;
use devtools::do_devtools_server_inner;
use tracing::metadata::LevelFilter;

use std::{
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use net_decode::{
    chomp::{self, EthernetChomper},
    http::{HTTPRequestTracker, HTTPStreamEvent},
    key_db::KeyDB,
    listener::{DebugListener, Listener},
    tcp_reassemble::TcpFollower,
    tls::TLSFlowTracker,
};
use tracing_subscriber::prelude::*;

#[cfg(target_os = "linux")]
mod capture;
mod devtools;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(clap::Parser, Debug)]
enum Command {
    /// Debug: run a pcap through the clipper network stack
    DumpPcap { file: PathBuf },
    /// Starts a devtools server on a pcapng file.
    DevtoolsServer { file: PathBuf },
    /// Invokes a program with capture. Does not require root on Linux.
    Capture {
        /// File to write a pcapng to.
        #[clap(short = 'o', long)]
        output_file: PathBuf,

        /// Arguments for the program to invoke.
        #[clap(num_args = 0..)]
        args: Vec<String>,
    },
    /// Serves a devtools server while capturing packets
    CaptureDevtools {
        /// Arguments for the program to invoke.
        #[clap(num_args = 0..)]
        args: Vec<String>,
    },
}

pub fn chomper(
    http_listener: Box<dyn Listener<HTTPStreamEvent>>,
    key_db: Arc<RwLock<KeyDB>>,
) -> EthernetChomper<TLSFlowTracker> {
    EthernetChomper {
        tcp_follower: TcpFollower::default(),
        recv: TLSFlowTracker::new(
            key_db.clone(),
            Box::new(HTTPRequestTracker::new(http_listener)),
        ),
        key_db,
    }
}

fn do_dump_pcap(file: PathBuf) -> Result<(), Error> {
    let key_db = Arc::new(RwLock::new(KeyDB::default()));
    let mut chomper = chomper(Box::new(DebugListener {}), key_db.clone());

    chomp::dump_pcap_file(file, &mut chomper)?;
    Ok(())
}

fn do_devtools_server(file: PathBuf) -> Result<(), Error> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(do_devtools_server_inner(file))
}

fn main() -> Result<(), Error> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::Layer::new().without_time())
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Command::parse();

    match args {
        Command::DumpPcap { file } => do_dump_pcap(file)?,
        Command::DevtoolsServer { file } => do_devtools_server(file)?,
        #[cfg(target_os = "linux")]
        Command::Capture { args, output_file } => capture::do_capture_to_pcap(output_file, args)?,
        #[cfg(target_os = "linux")]
        Command::CaptureDevtools { args } => capture::do_capture_to_devtools(args)?,
    }
    Ok(())
}
