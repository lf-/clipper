// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! The Clipper CLI.
use clap::Parser;
use libclipper::{devtools::do_devtools_server_inner, Error};
use tracing::metadata::LevelFilter;

use std::{
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use net_decode::{
    chomp::{self},
    key_db::KeyDB,
    listener::DebugListener,
};
use tracing_subscriber::prelude::*;

#[derive(clap::Parser, Debug)]
enum Command {
    /// Debug: run a pcap through the clipper network stack
    DumpPcap { file: PathBuf },
    /// Starts a devtools server on a pcapng file.
    DevtoolsServer { file: PathBuf },
    /// Anonymizes the addresses in a pcapng file.
    Anonymize {
        /// File to read from
        #[clap(short = 'i', long)]
        input_file: PathBuf,
        /// File to write to
        #[clap(short = 'o', long)]
        output_file: PathBuf,
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
    /// Serves a devtools server while capturing packets
    CaptureDevtools {
        /// Arguments for the program to invoke.
        #[clap(num_args = 0..)]
        args: Vec<String>,
    },
}

fn do_dump_pcap(file: PathBuf) -> Result<(), Error> {
    let key_db = Arc::new(RwLock::new(KeyDB::default()));
    let mut chomper = net_decode::chomper(DebugListener {}, key_db.clone());

    chomp::dump_pcap_file(file, &mut chomper)?;
    Ok(())
}

fn do_devtools_server(file: PathBuf) -> Result<(), Error> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(do_devtools_server_inner(file))
}

fn do_anonymize(input_file: PathBuf, output_file: PathBuf) -> Result<(), Error> {
    use std::{fs, io};
    let mut reader = io::BufReader::new(fs::OpenOptions::new().read(true).open(input_file)?);
    let mut writer = io::BufWriter::new(
        fs::OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(output_file)?,
    );

    anon_packets::process_pcap(&mut reader, &mut writer)
}

fn fixup_args(args: Vec<String>) -> Vec<String> {
    if args.is_empty() {
        vec![std::env::var("SHELL").unwrap_or("sh".into())]
    } else {
        args
    }
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
        Command::Anonymize {
            input_file,
            output_file,
        } => do_anonymize(input_file, output_file)?,
        #[cfg(target_os = "linux")]
        Command::Capture { args, output_file } => {
            libclipper::capture::do_capture_to_pcap(output_file, fixup_args(args))?
        }
        #[cfg(target_os = "linux")]
        Command::CaptureDevtools { args } => {
            libclipper::capture::do_capture_to_devtools(fixup_args(args))?
        }
    }
    Ok(())
}
