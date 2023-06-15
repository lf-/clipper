//! Does a similar thing to the following:
//! https://github.com/rusticata/pcap-analyzer/blob/master/libpcap-analyzer/src/tcp_reassembly.rs#L14
use pktparse::tcp::TcpHeader;

use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap},
    fmt::{self, Debug},
    num::Wrapping,
    ops::Bound,
};

use crate::{chomp::IPHeader, chomp::IPTarget, Error};

/// https://datatracker.ietf.org/doc/html/rfc9293#name-state-machine-overview
#[allow(unused)]
#[derive(Clone, Copy, Debug)]
pub enum TCPState {
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

type SeqNum = Wrapping<u32>;

pub trait ReassemblerTarget<H> {
    /// Called when the expected segment lands in the reorder buffer.
    ///
    /// Returns the next expected sequence number.
    fn on_good_segment(&mut self, data: H) -> SeqNum;
}

impl<H: HasSequenceNumber, F: FnMut(H) -> SeqNum> ReassemblerTarget<H> for F {
    fn on_good_segment(&mut self, data: H) -> SeqNum {
        self(data)
    }
}

pub trait HasSequenceNumber {
    fn sequence_number(&self) -> SeqNum;
}

impl HasSequenceNumber for (TcpHeader, Vec<u8>) {
    fn sequence_number(&self) -> SeqNum {
        Wrapping(self.0.sequence_no)
    }
}

/// Reorder buffer for TCP segments.
///
/// Expects that the segment numbers are reasonable before input or else memory
/// may be leaked/order may not be preserved.
///
/// Returns segments strictly in-order and containing strictly all expected
/// data, but potentially with Bonus Data if they overlap.
#[derive(Default, Debug)]
pub struct TcpReorderBuffer<H: HasSequenceNumber> {
    /// The lowest maybe-stored, maybe-unavailable sequence number. Used to
    /// start search for blocks when extracting data.
    lowest: Wrapping<u32>,
    reassemble: BTreeMap<Wrapping<u32>, H>,
}

impl<H: HasSequenceNumber> TcpReorderBuffer<H> {
    pub fn new(isn: Wrapping<u32>) -> TcpReorderBuffer<H> {
        TcpReorderBuffer {
            lowest: isn,
            reassemble: BTreeMap::new(),
        }
    }

    /// Ingests a TCP segment and may call the callback some number of times to
    /// clear the queue if there is all necessary data.
    pub fn ingest<Target: ReassemblerTarget<H>>(&mut self, data: H, callback: &mut Target) {
        let incoming_seqno = data.sequence_number();
        // Ingest the data always
        self.reassemble.insert(incoming_seqno, data);

        // This ensures that incoming_seqno is never less than self.lowest,
        // to the extent that we can know that
        assert!(incoming_seqno - self.lowest < Wrapping(u32::MAX / 2));

        // Export all the data we can
        let mut it = WrappingCursor::new(&mut self.reassemble, self.lowest);
        loop {
            let pos = it.peek().map(|(k, _v)| *k);
            if let Some(k) = pos {
                if k == self.lowest {
                    // We have the data for the current lowest, take it out
                    let (_, v) = it.remove().unwrap();
                    self.lowest = callback.on_good_segment(v);
                } else {
                    // We don't have the segment we want yet.
                    break;
                }
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct TCPStateMachine {
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
}

#[derive(Debug, Default)]
pub struct TCPSide {
    state_machine: TCPStateMachine,

    reorder_buffer: TcpReorderBuffer<(TcpHeader, Vec<u8>)>,
}

impl TCPStateMachine {
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

#[derive(Debug)]
pub struct TCPFlow {
    /// State machine maintained for data received by the client side
    pub client: TCPSide,
    /// State machine maintained for data received by the server side
    pub server: TCPSide,
}

pub trait TCPFlowReceiver {
    // FIXME: should this be modified to include a downstream function in its
    // signature?
    fn on_data(&mut self, target: IPTarget, to_client: bool, data: Vec<u8>);
}

#[derive(Debug, Default)]
pub struct NoOpTCPFlowReceiver {}

impl TCPFlowReceiver for NoOpTCPFlowReceiver {
    fn on_data(&mut self, _target: IPTarget, _to_client: bool, _data: Vec<u8>) {
        // do nothing! :D
    }
}

#[derive(Debug, Default)]
pub struct HexDumpTCPFlowReceiver {}

impl TCPFlowReceiver for HexDumpTCPFlowReceiver {
    fn on_data(&mut self, target: IPTarget, to_client: bool, data: Vec<u8>) {
        tracing::info!(
            "tcp {target:?} to_client={to_client}:\n{}",
            hexdump::HexDumper::new(&data)
        );
    }
}

#[derive(Debug, Default)]
pub struct TcpFollower {
    /// Drives a TCP state machine based on the data received on a given side.
    pub flows: HashMap<IPTarget, TCPFlow>,
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
        recv: &mut dyn TCPFlowReceiver,
    ) -> Result<(), Error> {
        let received_by_client = self.flows.contains_key(&target.flip());
        let entry_key = if received_by_client {
            // the reverse of the flow exists, so it's sent by the server
            target.flip()
        } else {
            *target
        };
        let entry = self.flows.entry(entry_key);

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
                        state_machine: TCPStateMachine {
                            state: TCPState::SynSent,
                            ..TCPStateMachine::default()
                        },
                        ..TCPSide::default()
                    },
                    server: TCPSide {
                        state_machine: TCPStateMachine {
                            state: TCPState::Listen,
                            ..TCPStateMachine::default()
                        },
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
            rx_side.state_machine.state,
            target,
            PrintTcpHeader(&tcp)
        );

        // FIXME: this state handling is a tangled disaster and needs to be
        // untangled. but whatever lmao
        match rx_side.state_machine.state {
            TCPState::Listen | TCPState::SynSent | TCPState::SynReceived => {
                // In these states, the TCP state machine has not yet
                // synchronized the sequence numbers, so we cannot reorder
                // packets yet.
                rx_side.state_machine.drive_state(tcp, |_side| {
                    // We expect empty SYN and SYN-ACK packets
                    assert_eq!(0, data.len());
                });
                rx_side.reorder_buffer.lowest = Wrapping(rx_side.state_machine.rcv_next);
            }
            _ => {
                rx_side.reorder_buffer.ingest(
                    (tcp.clone(), data.to_vec()),
                    &mut |(header, bs): (TcpHeader, Vec<u8>)| {
                        let new_rcv_next =
                            Wrapping(header.sequence_no) + Wrapping(bs.len().try_into().unwrap());

                        // Now have in-order segments, so we can do things with them
                        tracing::debug!("data: {}", hexdump::HexDumper::new(&bs));
                        // FIXME: edge cases:
                        // * Receive a seqnum which is LESS THAN the one
                        // expected: perhaps for some reason we got part of a
                        // buffer sent twice
                        // * Receive an old seqnum twice (currently I think it
                        // throws an assert).
                        rx_side.state_machine.drive_state(&header, |_side| {
                            // they gave us buffer uwu
                            recv.on_data(entry_key, received_by_client, bs);
                        });

                        rx_side.state_machine.rcv_next = new_rcv_next.0;

                        new_rcv_next
                    },
                );
            }
        }

        Ok(())
    }

    pub fn chomp(
        &mut self,
        ip_header: IPHeader,
        data: &[u8],
        recv: &mut dyn TCPFlowReceiver,
    ) -> Result<(), Error> {
        let proto = ip_header.proto();
        match proto {
            pktparse::ip::IPProtocol::TCP => {
                if let Ok((remain, tcp)) = pktparse::tcp::parse_tcp_header(data) {
                    let ip_target = IPTarget::from_headers(&ip_header, &tcp);
                    self.record_flow(&ip_target, &tcp, remain, recv)?;
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

/// Cursor that wraps around the start of the map. This is kinda a Strange
/// implementation to throw away the cursor every time, but I don't think
/// there's much other way to implement something like it.
///
/// XXX: this is pretty semantically strange, since the position need not
/// actually *exist* in the map: it may not be here yet!
struct WrappingCursor<'a, K, V> {
    map: &'a mut BTreeMap<K, V>,
    pos: Option<K>,
}

impl<'a, K: Clone + Ord, V> WrappingCursor<'a, K, V> {
    /// Does not necessarily expect that the given key is in the map: you may
    /// have not gotten it yet.
    pub fn new(map: &'a mut BTreeMap<K, V>, start_at: K) -> Self {
        WrappingCursor {
            map,
            pos: Some(start_at),
        }
    }

    // XXX: borrow checker hack: splitting the borrow of self
    fn peek_next_inner(map: &'a BTreeMap<K, V>, pos: &K) -> Option<(&'a K, &'a V)> {
        map.range((Bound::Excluded(pos), Bound::Unbounded))
            .next()
            .or_else(||
            // No more elements on this end of the map, maybe there are some at
            // the start?
            map.first_key_value())
    }

    fn peek_inner(map: &'a BTreeMap<K, V>, pos: &K) -> Option<(&'a K, &'a V)> {
        map.range((Bound::Included(pos), Bound::Unbounded))
            .next()
            .or_else(||
            // No more elements on this end of the map, maybe there are some at
            // the start?
            map.first_key_value())
    }

    /// Peeks at the current position of the iterator.
    pub fn peek(&'a self) -> Option<(&'a K, &'a V)> {
        let pos = self.pos.as_ref()?;
        Self::peek_inner(&self.map, pos)
    }

    /// Gets the current position
    pub fn pos(&self) -> Option<K> {
        self.pos.clone()
    }

    /// Peeks at the *next* value of the iterator.
    pub fn peek_next(&'a self) -> Option<(&'a K, &'a V)> {
        let pos = self.pos.as_ref()?;
        Self::peek_next_inner(&self.map, pos)
    }

    // XXX: for reasons I don't feel like understanding right now, you cannot
    // make Iterator::next take &'a mut self and this is necessary to not get
    // borrowck on us. idk man.
    pub fn next(&'a mut self) -> Option<(&'a K, &'a V)> {
        let pos = self.pos.as_ref()?;
        if let Some((k, v)) = Self::peek_next_inner(&self.map, pos) {
            self.pos = Some(k.clone());
            Some((k, v))
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pos.is_some()
    }

    pub fn remove(&mut self) -> Option<(K, V)> {
        let next_k = self.peek_next().map(|(k, _v)| k.clone());
        let ret = self.map.remove_entry(self.pos.as_ref()?);
        self.pos = next_k;
        ret
    }
}

#[cfg(test)]
mod test {
    use proptest::{collection, prelude::*};

    use super::*;

    proptest! {
        fn next_expectations(ref mut map in collection::btree_map(1..10u32, 1..=1u32, (1, 4)), sel in any::<prop::sample::Selector>()) {
            // pick a map element at random
            let k = *sel.select(map.keys());

            let (&last_k, _) = map.last_key_value().unwrap();
            let (&first_k, _) = map.first_key_value().unwrap();
            let next_may = {
                let mut it = map.range(k..).map(|(k, _v)| (*k));
                it.next();
                it.next()
            };

            let mut curs = WrappingCursor::new(map, k);

            // Wraps around
            if k == last_k {
                prop_assert_eq!(Some(first_k), curs.peek_next().map(|(k, _)| *k));
                let (&should_be_first_k, _) = curs.next().unwrap();
                prop_assert_eq!(first_k, should_be_first_k);
            } else {
                // Works normally
                prop_assert_eq!(curs.peek_next().map(|(k, _)| *k), next_may);
            }
        }
    }

    #[test]
    fn test_wrapping_cursor() {
        next_expectations();
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeSegment {
        seqno: SeqNum,
        len: SeqNum,
    }

    impl FakeSegment {
        fn new(seqno: u32, len: u32) -> FakeSegment {
            FakeSegment {
                seqno: Wrapping(seqno),
                len: Wrapping(len),
            }
        }
    }

    impl HasSequenceNumber for FakeSegment {
        fn sequence_number(&self) -> SeqNum {
            self.seqno
        }
    }

    #[derive(Clone, Debug, Default)]
    struct SegmentTracer {
        seen: Vec<FakeSegment>,
    }

    impl ReassemblerTarget<FakeSegment> for SegmentTracer {
        fn on_good_segment(&mut self, data: FakeSegment) -> SeqNum {
            let new_num = data.seqno + data.len;
            self.seen.push(data);
            new_num
        }
    }

    #[test]
    fn test_segment_reordering() {
        let mut tracer = SegmentTracer::default();

        let mut rb = TcpReorderBuffer::new(Wrapping(u32::MAX - 5));
        let a = u32::MAX - 5;
        let alen = 6;
        let b = a.wrapping_add(alen);
        let blen = 7;

        rb.ingest(FakeSegment::new(b, blen), &mut tracer);
        assert_eq!(&Vec::<FakeSegment>::new(), &tracer.seen);
        rb.ingest(FakeSegment::new(a, alen), &mut tracer);
        assert_eq!(
            &vec![FakeSegment::new(a, alen), FakeSegment::new(b, blen)],
            &tracer.seen
        );
    }
}
