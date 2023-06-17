use crate::{key_db::KeyDB, listener::Listener, tcp_reassemble::TcpFollower, Error};
use pcap_parser::{
    traits::{PcapNGPacketBlock, PcapReaderIterator},
    PcapError, PcapNGReader,
};
use pktparse::{ethernet::EtherType, tcp::TcpHeader};
use std::{
    fmt::{self, Debug},
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tracing::Level;

#[derive(Clone, Debug)]
pub enum IPHeader {
    V4(pktparse::ipv4::IPv4Header),
    V6(pktparse::ipv6::IPv6Header),
}

impl IPHeader {
    pub fn proto(&self) -> pktparse::ip::IPProtocol {
        match self {
            IPHeader::V4(v4) => v4.protocol,
            IPHeader::V6(v6) => v6.next_header,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPTarget {
    V4 {
        client_port: u16,
        server_port: u16,
        client_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
    },
    V6 {
        client_port: u16,
        server_port: u16,
        client_ip: Ipv6Addr,
        server_ip: Ipv6Addr,
    },
}

impl Debug for IPTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 {
                client_port: source_port,
                server_port: dest_port,
                client_ip: source_ip,
                server_ip: dest_ip,
            } => {
                write!(f, "{source_ip:?}:{source_port} -> {dest_ip:?}:{dest_port}")
            }
            Self::V6 {
                client_port: source_port,
                server_port: dest_port,
                client_ip: source_ip,
                server_ip: dest_ip,
            } => {
                write!(
                    f,
                    "[{source_ip:?}]:{source_port} -> [{dest_ip:?}]:{dest_port}"
                )
            }
        }
    }
}

impl IPTarget {
    pub fn from_headers(ip: &IPHeader, tcp: &TcpHeader) -> IPTarget {
        match ip {
            IPHeader::V4(v4) => IPTarget::V4 {
                client_port: tcp.source_port,
                server_port: tcp.dest_port,
                client_ip: v4.source_addr,
                server_ip: v4.dest_addr,
            },
            IPHeader::V6(v6) => IPTarget::V6 {
                client_port: tcp.source_port,
                server_port: tcp.dest_port,
                client_ip: v6.source_addr,
                server_ip: v6.dest_addr,
            },
        }
    }

    pub fn server_port(&self) -> u16 {
        match self {
            IPTarget::V4 { server_port, .. } => *server_port,
            IPTarget::V6 { server_port, .. } => *server_port,
        }
    }

    pub fn flip(self) -> IPTarget {
        match self {
            IPTarget::V4 {
                client_port: source_port,
                server_port: dest_port,
                client_ip: source_ip,
                server_ip: dest_ip,
            } => IPTarget::V4 {
                client_port: dest_port,
                server_port: source_port,
                client_ip: dest_ip,
                server_ip: source_ip,
            },
            IPTarget::V6 {
                client_port: source_port,
                server_port: dest_port,
                client_ip: source_ip,
                server_ip: dest_ip,
            } => IPTarget::V6 {
                client_port: dest_port,
                server_port: source_port,
                client_ip: dest_ip,
                server_ip: source_ip,
            },
        }
    }
}

pub struct PacketChomper<Recv: Listener<Vec<u8>>> {
    pub tcp_follower: TcpFollower,
    pub recv: Recv,
}

impl<Recv: Listener<Vec<u8>>> PacketChomper<Recv> {
    fn chomp(&mut self, packet: &[u8]) -> Result<(), Error> {
        if let Ok((remain, frame)) = pktparse::ethernet::parse_ethernet_frame(&packet) {
            // tracing::debug!("frame! {:?}", &frame);
            match frame.ethertype {
                EtherType::IPv4 => {
                    if let Ok((remain, pkt)) = pktparse::ipv4::parse_ipv4_header(remain) {
                        // tracing::debug!("ipv4 pakit! {:?}", &pkt);
                        self.tcp_follower
                            .chomp(IPHeader::V4(pkt), remain, &mut self.recv)?;
                    }
                }
                EtherType::IPv6 => {
                    if let Ok((remain, pkt)) = pktparse::ipv6::parse_ipv6_header(remain) {
                        tracing::debug!("ipv6 pakit! {:?}", &pkt);
                        self.tcp_follower
                            .chomp(IPHeader::V6(pkt), remain, &mut self.recv)?;
                    }
                }
                _ => {
                    tracing::warn!(
                        "ignored frame with unsupported ethertype {:?}",
                        frame.ethertype
                    );
                }
            }
        }
        Ok(())
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

pub fn dump_pcap<Recv: Listener<Vec<u8>>>(
    file: PathBuf,
    chomper: &mut PacketChomper<Recv>,
    key_db: Arc<RwLock<KeyDB>>,
) -> Result<(), Error> {
    let contents = std::fs::read(file)?;

    let mut pcap = PcapNGReader::new(65536, Cursor::new(contents))?;

    let mut packet_count = 1u64;

    loop {
        match pcap.next() {
            Ok((offset, block)) => {
                let span = tracing::span!(Level::DEBUG, "packet", count = packet_count);
                let _enter = span.enter();
                match block {
                    pcap_parser::PcapBlockOwned::NG(block) => {
                        match block {
                            pcap_parser::Block::DecryptionSecrets(dsb) => {
                                tracing::debug!(
                                    "DSB: {}",
                                    Show(&dsb.data[..dsb.secrets_len as usize])
                                );
                                let mut kdb = key_db.write().unwrap();
                                kdb.load_key_log(&dsb.data[..dsb.secrets_len as usize]);
                            }
                            pcap_parser::Block::EnhancedPacket(epb) => {
                                chomper.chomp(epb.packet_data()).unwrap();
                                packet_count += 1;
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
