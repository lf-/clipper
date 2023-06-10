//! Command-line debugging tool for clipper to exercise pcap and network
//! protocol functionality before the rest of the system is built.
use clap::Parser;
use pcap_parser::{
    traits::{PcapNGPacketBlock, PcapReaderIterator},
    PcapError, PcapNGReader,
};
use pktparse::{ethernet::EtherType, tcp::TcpHeader};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Debug},
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};
use tracing::Level;
use tracing_subscriber::prelude::*;

type Error = Box<dyn std::error::Error>;

#[derive(clap::Parser, Debug)]
enum Command {
    DumpPcap { file: PathBuf },
}

#[derive(Clone, Debug)]
enum IPHeader {
    V4(pktparse::ipv4::IPv4Header),
    V6(pktparse::ipv6::IPv6Header),
}

impl IPHeader {
    fn proto(&self) -> pktparse::ip::IPProtocol {
        match self {
            IPHeader::V4(v4) => v4.protocol,
            IPHeader::V6(v6) => v6.next_header,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum IPTarget {
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
    fn from_headers(ip: &IPHeader, tcp: &TcpHeader) -> IPTarget {
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

    fn flip(self) -> IPTarget {
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

/// https://datatracker.ietf.org/doc/html/rfc9293#name-state-machine-overview
#[derive(Clone, Copy, Debug)]
enum TCPState {
    /// "Represents waiting for a connection request from any remote TCP peer
    /// and port"
    Listen,
    /// "Represents waiting for a matching connection request after having sent
    /// a connection request"
    SynSent,
    /// "Represents waiting for a confirming connection request acknowledgment
    /// after having both received and sent a connection request"
    SynReceived,
    /// "Represents an open connection, data received can be delivered to the
    /// user. The normal state for the data transfer phase of the connection"
    Established,
    /// "Represents waiting for a connection termination request from the
    /// remote TCP peer, or an acknowledgment of the connection termination
    /// request previously sent"
    FinWait1,
    /// "Represents waiting for a connection termination request from the
    /// remote TCP peer."
    FinWait2,
    /// "Represents waiting for a connection termination request from the local
    /// user"
    CloseWait,
    /// "Represents waiting for a connection termination request acknowledgment
    /// from the remote TCP peer"
    Closing,
    /// "Represents waiting for an acknowledgment of the connection termination
    /// request previously sent to the remote TCP peer (this termination
    /// request sent to the remote TCP peer already included an acknowledgment
    /// of the termination request sent from the remote TCP peer)."
    LastAck,
    /// "Represents waiting for enough time to pass to be sure the remote TCP
    /// peer received the acknowledgment of its connection termination request
    /// and to avoid new connections being impacted by delayed segments from
    /// previous connections."
    TimeWait,
    /// "Represents no connection state at all."
    Closed,
}

impl Default for TCPState {
    fn default() -> Self {
        TCPState::Closed
    }
}

#[derive(Clone, Debug, Default)]
struct TCPSide {
    pub state: TCPState,

    /// initial receive sequence number
    irs: u32,
    /// expected next received sequence number
    rcv_next: u32,

    /// initial send sequence number
    iss: u32,
    /// FIXME:
    send_next: u32,
    /// Last unacknowledged sequence number (SND.UNA)
    send_unack: u32,

    // FIXME: how do we get stuff OUT of the buffer before we run out of window
    // size? implementing PUSH?
    pub data: Vec<u8>,
}

impl TCPSide {
    fn drive_state(&mut self, tcp: &TcpHeader, process_data: impl FnOnce(&mut Self)) {
        let flag_syn = tcp.flag_syn;
        let flag_ack = tcp.flag_ack;
        let flag_rst = tcp.flag_rst;
        let flag_fin = tcp.flag_fin;

        // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.2
        match self.state {
            TCPState::Closed => return,
            TCPState::Listen => {
                // First, check for a RST
                if flag_rst {
                    return;
                }

                // All ACKs in Listen are bad.
                if flag_ack {
                    return;
                }

                if flag_syn {
                    self.rcv_next = tcp.sequence_no.wrapping_add(1);
                    self.irs = tcp.sequence_no;
                    // NOTE: we don't KNOW what ISS is because we don't get to
                    // send it! This will be fixed by recovering the ISS in
                    // SynReceived.
                    // SND.NXT = ISS+1
                    // SND.UNA = ISS
                    self.state = TCPState::SynReceived;
                }
            }
            TCPState::SynSent => {
                // XXX: fixup of ISS
                self.iss = tcp.ack_no.wrapping_sub(1);
                self.send_next = self.iss.wrapping_add(1);
                self.send_unack = self.iss;

                if flag_ack {
                    if tcp.ack_no <= self.iss || tcp.ack_no > self.send_next {
                        tracing::debug!("3.10.7.3 dropped packet");
                        return;
                    }
                }

                if flag_rst {
                    return;
                }

                if flag_syn {
                    self.rcv_next = tcp.sequence_no.wrapping_add(1);
                    self.irs = tcp.sequence_no;

                    if flag_ack {
                        self.send_unack = tcp.ack_no;
                    }

                    if self.send_unack > self.iss {
                        self.state = TCPState::Established;
                    } else {
                        // FIXME: SND.WND, SND.WL1, SND.WL2
                        self.state = TCPState::SynReceived;
                    }
                }
            }
            TCPState::SynReceived => {
                if flag_syn {
                    // most likely the correct option here is to return to
                    // LISTEN per 3.10.7.4
                    self.state = TCPState::Listen;
                    return;
                }

                // XXX: fixup of ISS
                self.iss = tcp.ack_no.wrapping_sub(1);
                self.send_next = self.iss.wrapping_add(1);
                self.send_unack = self.iss;

                if flag_ack {
                    if self.send_unack < tcp.ack_no && tcp.ack_no <= self.send_next {
                        // FIXME:
                        // SND.WND = SEG.WND
                        // SND.WL1 = SEG.SEQ
                        // SND.WL2 = SEG.ACK
                        self.state = TCPState::Established;
                    }
                }
            }
            TCPState::Established => {
                if self.send_unack < tcp.ack_no && tcp.ack_no <= self.send_next {
                    self.send_unack = tcp.ack_no;
                }

                process_data(self);

                // FIXME: this is definitely wrong, but it's unclear how we
                // should act as a non-speaking TCP implementation
                if flag_fin {
                    self.state = TCPState::Closed;
                }
            }
            _ => {
                tracing::debug!("FIXME: unimplemented tcp state {self:?}");
            }
        };
    }
}

#[derive(Clone, Debug)]
struct TCPFlow {
    /// State machine maintained for data received by the client side
    client: TCPSide,
    /// State machine maintained for data received by the server side
    server: TCPSide,
}

#[derive(Clone, Debug, Default)]
struct TcpFollower {
    /// Drives a TCP state machine based on the data received on a given side.
    flows: HashMap<IPTarget, TCPFlow>,
}

struct PrintTcpHeader<'a>(&'a TcpHeader);

impl<'a> Debug for PrintTcpHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut field = |name: &str, val| -> fmt::Result {
            if val {
                write!(f, "{name} ")
            } else {
                for _ in 0..name.len() + 1 {
                    write!(f, " ")?
                }
                Ok(())
            }
        };
        field("SYN", self.0.flag_syn)?;
        field("ACK", self.0.flag_ack)?;
        field("FIN", self.0.flag_fin)?;
        write!(f, "{:?}", self.0)
    }
}

impl TcpFollower {
    fn record_flow(
        &mut self,
        target: &IPTarget,
        tcp: &TcpHeader,
        data: &[u8],
    ) -> Result<(), Error> {
        let received_by_client = self.flows.contains_key(&target.flip());
        let entry = if received_by_client {
            // the reverse of the flow exists, so it's sent by the server
            self.flows.entry(target.flip())
        } else {
            self.flows.entry(*target)
        };

        let entry = match entry {
            Entry::Vacant(_) if received_by_client => unreachable!(),
            // Flow that we are probably missing the front of
            Entry::Vacant(_) if !received_by_client && (!tcp.flag_syn || tcp.flag_ack) => {
                tracing::debug!("drop unk flow {target:?}");
                return Ok(());
            }
            Entry::Vacant(v) => {
                // We are client-sent, and need to init the connection
                v.insert(TCPFlow {
                    client: TCPSide {
                        state: TCPState::SynSent,
                        ..TCPSide::default()
                    },
                    server: TCPSide {
                        state: TCPState::Listen,
                        ..TCPSide::default()
                    },
                })
            }
            Entry::Occupied(v) => v.into_mut(),
        };

        let rx_side = if received_by_client {
            &mut entry.client
        } else {
            &mut entry.server
        };
        let side_label = if received_by_client {
            "client"
        } else {
            "server"
        };

        tracing::debug!(
            "tcp {side_label} {:?} {:?} {:?}",
            rx_side.state,
            target,
            PrintTcpHeader(&tcp)
        );

        rx_side.drive_state(tcp, |entry| {
            let start = tcp.sequence_no.wrapping_sub(entry.rcv_next);
            tracing::debug!("accept start={start}");
            entry
                .data
                .resize(entry.data.len().max(start as usize + data.len()), 0);
            entry.data[start as usize..start as usize + data.len()].copy_from_slice(data);
        });

        Ok(())
    }

    fn chomp(&mut self, ip_header: IPHeader, data: &[u8]) -> Result<(), Error> {
        let proto = ip_header.proto();
        match proto {
            pktparse::ip::IPProtocol::TCP => {
                if let Ok((remain, tcp)) = pktparse::tcp::parse_tcp_header(data) {
                    let ip_target = IPTarget::from_headers(&ip_header, &tcp);
                    self.record_flow(&ip_target, &tcp, remain)?;
                    tracing::debug!("\n{}", hexdump::HexDumper::new(remain));
                }
            }
            p => {
                tracing::debug!("unk protocol {p:?}");
            }
        }
        Ok(())
    }
}

struct PacketChomper {
    pub tcp_follower: TcpFollower,
}

impl PacketChomper {
    fn chomp(&mut self, packet: &[u8]) -> Result<(), Error> {
        if let Ok((remain, frame)) = pktparse::ethernet::parse_ethernet_frame(&packet) {
            // tracing::debug!("frame! {:?}", &frame);
            match frame.ethertype {
                EtherType::IPv4 => {
                    if let Ok((remain, pkt)) = pktparse::ipv4::parse_ipv4_header(remain) {
                        // tracing::debug!("ipv4 pakit! {:?}", &pkt);
                        self.tcp_follower.chomp(IPHeader::V4(pkt), remain)?;
                    }
                }
                EtherType::IPv6 => {
                    if let Ok((remain, pkt)) = pktparse::ipv6::parse_ipv6_header(remain) {
                        tracing::debug!("ipv6 pakit! {:?}", &pkt);
                        self.tcp_follower.chomp(IPHeader::V6(pkt), remain)?;
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

fn dump_pcap(file: PathBuf) -> Result<(), Error> {
    let contents = std::fs::read(file)?;

    let mut pcap = PcapNGReader::new(65536, Cursor::new(contents))?;
    let mut chomper = PacketChomper {
        tcp_follower: TcpFollower::default(),
    };

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
                                )
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

    for (flow, data) in chomper.tcp_follower.flows {
        tracing::debug!(
            "flow: {flow:?}, data:\n{}\n{}",
            hexdump::HexDumper::new(&data.server.data),
            hexdump::HexDumper::new(&data.client.data)
        );
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::Layer::new().without_time())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Command::parse();

    match args {
        Command::DumpPcap { file } => {
            dump_pcap(file)?;
        }
    }
    Ok(())
}
