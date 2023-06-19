//! Command-line debugging tool for clipper to exercise pcap and network
//! protocol functionality before the rest of the system is built.
use clap::Parser;
use devtools::do_devtools_server_inner;
use wire_blahaj::unprivileged::run_in_ns;

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
    Capture {
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

fn do_capture(args: Vec<String>) -> Result<(), Error> {
    unsafe { run_in_ns(args, |_| {})? };
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
        Command::Capture { args } => do_capture(args)?,
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
