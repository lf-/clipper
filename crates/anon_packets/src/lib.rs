// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Packet anonymization library, designed to allow rewriting pcaps to remove
//! original addresses.

use std::{
    collections::HashMap,
    hash::Hash,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use cidr::{Ipv4Cidr, Ipv6Cidr};
use pcap_parser::{traits::PcapReaderIterator, ToVec};
use pnet_base::MacAddr;
use pnet_packet::{
    ethernet::{EtherType, EtherTypes},
    MutablePacket,
};
use rand::prelude::*;
use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaChaRng;

type Error = Box<dyn std::error::Error + Send + Sync>;

trait Mapping<T> {
    /// Remaps an IP address per the rules of this remapper. Will only be
    /// called once per input value.
    ///
    /// When this function returns None, it means that the remapping failed,
    /// and to not retry. The function may be run many times for the same input
    /// if a mapping would overlap an existing one. Try to have enough
    /// cardinality of the range for this to not be a problem.
    fn remap(&mut self, input: T) -> Option<T>;
}

struct Mapper<T: Hash> {
    mappings: HashMap<T, T>,
    downstream: Box<dyn Mapping<T>>,
}

impl<T: Hash + Copy + Eq> Mapper<T> {
    pub fn new(downstream: Box<dyn Mapping<T>>) -> Self {
        Self {
            downstream,
            mappings: Default::default(),
        }
    }

    pub fn remap(&mut self, input: T) -> Option<T> {
        if let Some(v) = self.mappings.get(&input) {
            return Some(*v);
        }

        for _ in 0..1000 {
            // Fill, since it is not present.
            if let Some(new) = self.downstream.remap(input) {
                if self.mappings.contains_key(&new) {
                    continue;
                }
                self.mappings.insert(input, new);
                return Some(new);
            } else {
                // Assumed to mean it failed.
                return None;
            }
        }
        None
    }
}

/// An IP address is mapped to a random new IP address in the same scope that
/// stays consistent within the run. The replacement addresses are not
/// determined by the input address: they are simply picked when a new address
/// is required.
struct IPScopeRemap {
    ip_rng: ChaChaRng,
}

const fn cidrv4((a, b, c, d): (u8, u8, u8, u8), prefix: u8) -> Ipv4Cidr {
    match Ipv4Cidr::new(Ipv4Addr::new(a, b, c, d), prefix) {
        Ok(v) => v,
        Err(_) => panic!("bad cidr"),
    }
}

const fn addr_part(start: u8, addr: u128) -> u16 {
    ((addr >> (128 - (start as u128) * 16)) & 0xffffu128) as u16
}

/// Required due to [`Ipv6Addr::from`] not being able to be const.
const fn ipv6addr_from_u128(addr: u128) -> Ipv6Addr {
    Ipv6Addr::new(
        addr_part(1, addr),
        addr_part(2, addr),
        addr_part(3, addr),
        addr_part(4, addr),
        addr_part(5, addr),
        addr_part(6, addr),
        addr_part(7, addr),
        addr_part(8, addr),
    )
}

const fn cidrv6(addr: u128, prefix: u8) -> Ipv6Cidr {
    match Ipv6Cidr::new(ipv6addr_from_u128(addr), prefix) {
        Ok(v) => v,
        Err(_) => panic!("bad cidr"),
    }
}

/// Example ranges:
/// 192.0.2.0/24 TEST-NET-1
/// 198.51.100.0/24 TEST-NET-2
/// 203.0.113.0/24 TEST-NET-3
static EXAMPLE_RANGES_V4: &[Ipv4Cidr] = &[
    cidrv4((192, 0, 2, 0), 24),
    cidrv4((198, 51, 100, 0), 24),
    cidrv4((203, 0, 113, 0), 24),
];

/// Private addresses:
/// 192.168.0.0/16
/// 172.16.0.0/12
/// 10.0.0.0/8
static PRIVATE_RANGES_V4: &[Ipv4Cidr] = &[
    cidrv4((192, 168, 0, 0), 16),
    cidrv4((172, 16, 0, 0), 12),
    cidrv4((10, 0, 0, 0), 8),
];

/// Multicast addresses:
/// 224.0.0.0/4
static MULTICAST_RANGE_V4: Ipv4Cidr = cidrv4((224, 0, 0, 0), 4);

/// Link-local addresses (APIPA):
/// 169.254.0.0/16
static LINK_LOCAL_RANGE_V4: Ipv4Cidr = cidrv4((169, 254, 0, 0), 16);

/// Loopback addresses:
/// 127.0.0.0/8
static LOOPBACK_RANGE_V4: Ipv4Cidr = cidrv4((127, 0, 0, 0), 8);

/// Example range:
/// 2001:db8::/32
static EXAMPLE_RANGE_V6: Ipv6Cidr = cidrv6(0x2001_0db8_0000_0000_0000_0000_0000_0000u128, 32);

/// Unique local addresses:
/// fc00::/7
static PRIVATE_RANGE_V6: Ipv6Cidr = cidrv6(0xfc00_0000_0000_0000_0000_0000_0000_0000u128, 7);

/// Multicast addresses:
/// ff00::/8
static MULTICAST_RANGE_V6: Ipv6Cidr = cidrv6(0xff00_0000_0000_0000_0000_0000_0000_0000u128, 8);

/// Link local addresses:
/// fe80::/64
static LINK_LOCAL_RANGE_V6: Ipv6Cidr = cidrv6(0xfe80_0000_0000_0000_0000_0000_0000_0000u128, 64);

#[derive(Clone, Copy, Debug)]
enum IPScope {
    Public,
    Example,
    LinkLocal,
    Private,
    Multicast,
    Broadcast,
    Loopback,
}

impl IPScopeRemap {
    pub fn new(seed: u64) -> Self {
        Self {
            ip_rng: ChaChaRng::seed_from_u64(seed),
        }
    }

    fn random_into_range_v4(random: u32, range: &Ipv4Cidr) -> Ipv4Addr {
        let addr_within = random & ((1u32 << (32 - range.network_length())) - 1);
        let net_part = u32::from_be_bytes(range.first_address().octets());

        let addr = Ipv4Addr::from(net_part | addr_within);
        assert!(range.contains(&addr));
        addr
    }

    /// Makes a random v4 address in the given scope
    fn next_v4(rng: &mut impl rand::Rng, scope: IPScope) -> Ipv4Addr {
        match scope {
            IPScope::Example | IPScope::Public => {
                let range = SliceRandom::choose(EXAMPLE_RANGES_V4, rng).unwrap();

                Self::random_into_range_v4(rng.gen::<u32>(), range)
            }
            IPScope::LinkLocal => {
                Self::random_into_range_v4(rng.gen::<u32>(), &LINK_LOCAL_RANGE_V4)
            }
            IPScope::Private => {
                let range = SliceRandom::choose(PRIVATE_RANGES_V4, rng).unwrap();

                Self::random_into_range_v4(rng.gen::<u32>(), range)
            }
            IPScope::Multicast => Self::random_into_range_v4(rng.gen::<u32>(), &MULTICAST_RANGE_V4),
            IPScope::Broadcast => Ipv4Addr::new(255, 255, 255, 255),
            // FIXME: technically could use any of the /8
            IPScope::Loopback => Ipv4Addr::new(127, 0, 0, 1),
        }
    }

    fn random_into_range_v6(random: u128, range: &Ipv6Cidr) -> Ipv6Addr {
        let addr_within = random & ((1u128 << (128 - range.network_length())) - 1);
        let net_part = u128::from_be_bytes(range.first_address().octets());

        let addr = Ipv6Addr::from(net_part | addr_within);
        assert!(range.contains(&addr));
        addr
    }

    fn next_v6(rng: &mut impl rand::Rng, scope: IPScope) -> Ipv6Addr {
        match scope {
            // FIXME: we should probably generate garbage public IPs too if
            // desired
            IPScope::Example | IPScope::Public => {
                Self::random_into_range_v6(rng.gen::<u128>(), &EXAMPLE_RANGE_V6)
            }
            IPScope::LinkLocal => {
                Self::random_into_range_v6(rng.gen::<u128>(), &LINK_LOCAL_RANGE_V6)
            }
            IPScope::Private => Self::random_into_range_v6(rng.gen::<u128>(), &PRIVATE_RANGE_V6),
            IPScope::Multicast => {
                Self::random_into_range_v6(rng.gen::<u128>(), &MULTICAST_RANGE_V6)
            }
            // Kind of meaningless in v6
            IPScope::Broadcast => Ipv6Addr::from(0xff02_0000_0000_0000_0000_0000_0000_0001u128),
            IPScope::Loopback => Ipv6Addr::from(0x1u128),
        }
    }

    fn scope_for_v4(addr: Ipv4Addr) -> IPScope {
        if EXAMPLE_RANGES_V4.iter().any(|r| r.contains(&addr)) {
            IPScope::Example
        } else if LINK_LOCAL_RANGE_V4.contains(&addr) {
            IPScope::LinkLocal
        } else if PRIVATE_RANGES_V4.iter().any(|r| r.contains(&addr)) {
            IPScope::Private
        } else if MULTICAST_RANGE_V4.contains(&addr) {
            IPScope::Multicast
        } else if addr == Ipv4Addr::new(255, 255, 255, 255) {
            IPScope::Broadcast
        } else if LOOPBACK_RANGE_V4.contains(&addr) {
            IPScope::Loopback
        } else {
            IPScope::Public
        }
    }

    fn scope_for_v6(addr: Ipv6Addr) -> IPScope {
        if EXAMPLE_RANGE_V6.contains(&addr) {
            IPScope::Example
        } else if LINK_LOCAL_RANGE_V6.contains(&addr) {
            IPScope::LinkLocal
        } else if PRIVATE_RANGE_V6.contains(&addr) {
            IPScope::Private
        } else if MULTICAST_RANGE_V6.contains(&addr) {
            IPScope::Multicast
        } else if addr.is_loopback() {
            IPScope::Loopback
        } else {
            IPScope::Public
        }
    }
}

impl Mapping<IpAddr> for IPScopeRemap {
    fn remap(&mut self, input: IpAddr) -> Option<IpAddr> {
        match input {
            IpAddr::V4(addr) => {
                let scope = Self::scope_for_v4(addr);
                let new = Self::next_v4(&mut self.ip_rng, scope);
                return Some(IpAddr::V4(new));
            }
            IpAddr::V6(addr) => {
                let scope = Self::scope_for_v6(addr);
                let new = Self::next_v6(&mut self.ip_rng, scope);
                return Some(IpAddr::V6(new));
            }
        }
    }
}

struct MacRandomRemap {
    rng: ChaChaRng,
}

impl MacRandomRemap {
    fn new(seed: u64) -> Self {
        Self {
            rng: ChaChaRng::seed_from_u64(seed),
        }
    }
}

impl Mapping<MacAddr> for MacRandomRemap {
    fn remap(&mut self, input: MacAddr) -> Option<MacAddr> {
        if input == MacAddr::broadcast() {
            return Some(MacAddr::broadcast());
        }

        const LOCALLY_ADMINISTERED: u8 = 1 << 1;
        const GROUP_ADDR: u8 = 1 << 0;

        let oct1 =
            (self.rng.gen::<u8>() & !GROUP_ADDR) | LOCALLY_ADMINISTERED | (input.0 & GROUP_ADDR);
        Some(MacAddr(
            oct1,
            self.rng.gen(),
            self.rng.gen(),
            self.rng.gen(),
            self.rng.gen(),
            self.rng.gen(),
        ))
    }
}

#[derive(Debug, Clone, thiserror::Error)]
enum DropReason {
    #[error("Failed to remap MAC address: {0}")]
    FailedToRemapMac(MacAddr),
    #[error("Failed to remap IP address: {0}")]
    FailedToRemapIp(IpAddr),
    #[error("Unknown ethertype: {0}")]
    UnkEthertype(EtherType),
    #[error("ICMPv6 is not yet supported")]
    Icmp6NotSupported,
    #[error("DNS is not yet supported")]
    DnsNotSupported,
    #[error("UDP parse failed")]
    UdpParseFailed,
    #[error("TCP parse failed")]
    TcpParseFailed,
    #[error("IP parse failed")]
    IpParseFailed,
    #[error("ARP parse failed")]
    ArpParseFailed,
    #[error("Ethernet parse failed")]
    EthernetParseFailed,
}

/// Deterministic (on the same input file) anonymizer for pcapng files.
struct Anonymizer {
    ip_remap: Mapper<IpAddr>,
    mac_remap: Mapper<MacAddr>,
}

impl Anonymizer {
    fn remap_v4(&mut self, addr: Ipv4Addr) -> Result<Ipv4Addr, DropReason> {
        match self
            .ip_remap
            .remap(IpAddr::V4(addr))
            .ok_or(DropReason::FailedToRemapIp(IpAddr::V4(addr)))?
        {
            IpAddr::V4(v) => Ok(v),
            IpAddr::V6(_) => unreachable!(),
        }
    }

    fn remap_v6(&mut self, addr: Ipv6Addr) -> Result<Ipv6Addr, DropReason> {
        match self
            .ip_remap
            .remap(IpAddr::V6(addr))
            .ok_or(DropReason::FailedToRemapIp(IpAddr::V6(addr)))?
        {
            IpAddr::V6(v) => Ok(v),
            IpAddr::V4(_) => unreachable!(),
        }
    }

    fn remap_mac(&mut self, addr: MacAddr) -> Result<MacAddr, DropReason> {
        self.mac_remap
            .remap(addr)
            .ok_or_else(|| DropReason::FailedToRemapMac(addr))
    }

    fn anonymize_l4_udp(&mut self, data: &mut [u8]) -> Result<(), DropReason> {
        let udp =
            pnet_packet::udp::MutableUdpPacket::new(data).ok_or(DropReason::UdpParseFailed)?;

        if udp.get_destination() == 53 {
            Err(DropReason::DnsNotSupported)
        } else {
            Ok(())
        }
    }

    fn anonymize_l4_tcp(&mut self, data: &mut [u8]) -> Result<(), DropReason> {
        let tcp =
            pnet_packet::tcp::MutableTcpPacket::new(data).ok_or(DropReason::TcpParseFailed)?;

        if tcp.get_destination() == 53 {
            Err(DropReason::DnsNotSupported)
        } else {
            Ok(())
        }
    }

    fn anonymize_l4(
        &mut self,
        proto: pnet_packet::ip::IpNextHeaderProtocol,
        data: &mut [u8],
    ) -> Result<(), DropReason> {
        // More specifically, drop protocols I don't want to implement yet.
        match proto {
            pnet_packet::ip::IpNextHeaderProtocols::Udp => self.anonymize_l4_udp(data),
            pnet_packet::ip::IpNextHeaderProtocols::Tcp => self.anonymize_l4_tcp(data),
            pnet_packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                // FIXME: We don't currently deal with ICMPv6, a fact which is kind of
                // broken
                return Err(DropReason::Icmp6NotSupported);
            }
            _ => Ok(()),
        }
    }

    fn anonymize_l3_ipv4(&mut self, data: &mut [u8]) -> Result<(), DropReason> {
        let mut packet =
            pnet_packet::ipv4::MutableIpv4Packet::new(data).ok_or(DropReason::IpParseFailed)?;

        let dest = packet.get_destination();
        packet.set_destination(self.remap_v4(dest)?);

        let src = packet.get_source();
        packet.set_source(self.remap_v4(src)?);

        let checksum = pnet_packet::ipv4::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);

        self.anonymize_l4(packet.get_next_level_protocol(), packet.payload_mut())
    }

    fn anonymize_l3_ipv6(&mut self, data: &mut [u8]) -> Result<(), DropReason> {
        let mut packet =
            pnet_packet::ipv6::MutableIpv6Packet::new(data).ok_or(DropReason::IpParseFailed)?;

        let dest = packet.get_destination();
        packet.set_destination(self.remap_v6(dest)?);

        let src = packet.get_source();
        packet.set_source(self.remap_v6(src)?);

        self.anonymize_l4(packet.get_next_header(), packet.payload_mut())
    }

    fn anonymize_l3_arp(&mut self, data: &mut [u8]) -> Result<(), DropReason> {
        let mut packet =
            pnet_packet::arp::MutableArpPacket::new(data).ok_or(DropReason::ArpParseFailed)?;

        let sender_hw = packet.get_sender_hw_addr();
        packet.set_sender_hw_addr(self.remap_mac(sender_hw)?);

        let recipient_hw = packet.get_target_hw_addr();
        packet.set_target_hw_addr(self.remap_mac(recipient_hw)?);

        let sender_proto = packet.get_sender_proto_addr();
        packet.set_sender_proto_addr(self.remap_v4(sender_proto)?);

        let target_proto = packet.get_target_proto_addr();
        packet.set_target_proto_addr(self.remap_v4(target_proto)?);

        Ok(())
    }

    /// Assumes that packet is ethernet (not necessarily always true; we would
    /// have to track interfaces to verify this)
    fn anonymize_l2_ethernet(&mut self, packet: &mut [u8]) -> Result<(), DropReason> {
        let mut p = pnet_packet::ethernet::MutableEthernetPacket::new(packet)
            .ok_or(DropReason::EthernetParseFailed)?;
        tracing::debug!(ethertype = ?p.get_ethertype(), src = ?p.get_source(), dest = ?p.get_destination(), "ethernet");

        match p.get_ethertype() {
            EtherTypes::Ipv4 => self.anonymize_l3_ipv4(p.payload_mut()),
            EtherTypes::Ipv6 => self.anonymize_l3_ipv6(p.payload_mut()),
            EtherTypes::Arp => self.anonymize_l3_arp(p.payload_mut()),
            other => {
                let et = other.0;
                tracing::warn!("unk ethertype {et:x}, dropping");
                Err(DropReason::UnkEthertype(other))
            }
        }?;
        let addr = p.get_source();
        p.set_source(self.remap_mac(addr)?);
        let addr = p.get_destination();
        p.set_destination(
            self.mac_remap
                .remap(addr)
                .ok_or_else(|| DropReason::FailedToRemapMac(addr))?,
        );

        // p.set_source();
        Ok(())
    }

    fn anonymize<'a>(&mut self, block: pcap_parser::Block<'a>) -> Option<Vec<u8>> {
        match block {
            pcap_parser::Block::EnhancedPacket(mut epb) => {
                let mut new_data = epb.data.to_vec();
                match self.anonymize_l2_ethernet(&mut new_data) {
                    Ok(()) => {
                        epb.data = &new_data;
                        epb.to_vec().ok()
                    }
                    Err(e) => {
                        tracing::warn!("Dropped packet: {e}");
                        None
                    }
                }
            }
            pcap_parser::Block::SimplePacket(_s) => {
                tracing::warn!("Discarded simple packet block");
                None
            }
            pcap_parser::Block::NameResolution(_nr) => {
                tracing::warn!("Discarded name resolution block");
                None
            }
            b => Some(b.to_vec_raw().unwrap()),
        }
    }
}

pub fn process_pcap(reader: impl io::Read, mut writer: impl io::Write) -> Result<(), Error> {
    let mut reader = pcap_parser::PcapNGReader::new(1_000_000, reader)?;
    let mut anonymizer = Anonymizer {
        ip_remap: Mapper::new(Box::new(IPScopeRemap::new(1337))),
        mac_remap: Mapper::new(Box::new(MacRandomRemap::new(1337))),
    };

    let mut frame_num = 0u64;

    while let Ok((size, block)) = reader.next() {
        let _scope = tracing::debug_span!("packet", ?frame_num);
        match block {
            pcap_parser::PcapBlockOwned::Legacy(_) => unreachable!(),
            pcap_parser::PcapBlockOwned::LegacyHeader(_) => unreachable!(),
            pcap_parser::PcapBlockOwned::NG(b) => {
                let b = anonymizer.anonymize(b);
                if let Some(b) = b {
                    writer.write(&b)?;
                }
            }
        }
        frame_num += 1;
        reader.consume(size);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ip_ranges() {
        let mut gen = ChaChaRng::seed_from_u64(1337);

        for _ in 1..1000 {
            let addr = IPScopeRemap::next_v4(&mut gen, IPScope::Example);
            let any_range_contains = EXAMPLE_RANGES_V4.iter().any(|r| r.contains(&addr));
            assert!(any_range_contains);
        }

        for _ in 1..1000 {
            let addr = IPScopeRemap::next_v6(&mut gen, IPScope::Example);
            assert!(EXAMPLE_RANGE_V6.contains(&addr));
        }
    }

    #[test]
    fn test_v6_construction() {
        let test = 0x112233445566778899aabbccddeeffu128;

        assert_eq!(ipv6addr_from_u128(test), Ipv6Addr::from(test));
    }
}
