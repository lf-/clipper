//! Command-line debugging tool for clipper to exercise pcap and network
//! protocol functionality before the rest of the system is built.
use clap::Parser;
use pcap_parser::{
    traits::{PcapNGPacketBlock, PcapReaderIterator},
    PcapError, PcapNGReader,
};
use std::{fmt, io::Cursor, path::PathBuf};

type Error = Box<dyn std::error::Error>;

#[derive(clap::Parser, Debug)]
enum Command {
    DumpPcap { file: PathBuf },
}

struct PacketChomper {}

impl PacketChomper {
    fn chomp(&mut self, packet: &[u8]) {
        println!("pakit! {:?}", packet);
    }
}

struct Show<'a>(&'a [u8]);
impl<'a> fmt::Display for Show<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for &ch in self.0 {
            for part in std::ascii::escape_default(ch) {
                fmt::Write::write_char(f, part as char)?;
            }
        }
        write!(f, "\"")
    }
}

fn dump_pcap(file: PathBuf) -> Result<(), Error> {
    let contents = std::fs::read(file)?;

    let mut pcap = PcapNGReader::new(65536, Cursor::new(contents))?;
    let mut chomper = PacketChomper {};

    loop {
        match pcap.next() {
            Ok((offset, block)) => {
                match block {
                    pcap_parser::PcapBlockOwned::NG(block) => {
                        match block {
                            pcap_parser::Block::DecryptionSecrets(dsb) => {
                                println!("{}", Show(&dsb.data[..dsb.secrets_len as usize]))
                            }
                            pcap_parser::Block::EnhancedPacket(epb) => {
                                chomper.chomp(epb.packet_data())
                            }
                            _ => {}
                        }
                        // println!("{:?}", block);
                    }
                    _ => unimplemented!(),
                }
                pcap.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                pcap.refill().unwrap();
            }
            Err(e) => panic!("error while parsing pcap {e:?}"),
        }
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    let args = Command::parse();

    match args {
        Command::DumpPcap { file } => {
            dump_pcap(file)?;
        }
    }
    Ok(())
}
