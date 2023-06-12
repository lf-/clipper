//! Command-line debugging tool for clipper to exercise pcap and network
//! protocol functionality before the rest of the system is built.
use clap::Parser;

use std::{fmt::Debug, path::PathBuf};

use net_decode::chomp;
use tracing_subscriber::prelude::*;

type Error = Box<dyn std::error::Error>;

#[derive(clap::Parser, Debug)]
enum Command {
    DumpPcap { file: PathBuf },
}

fn main() -> Result<(), Error> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::Layer::new().without_time())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Command::parse();

    match args {
        Command::DumpPcap { file } => {
            chomp::dump_pcap(file)?;
        }
    }
    Ok(())
}
