// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Support functionality for testing

use std::{
    fmt::{self, Write},
    sync::{Arc, RwLock},
};

use crate::{
    chomp::{EthernetChomper, FrameChomper},
    chomper,
    dispatch::{self, ListenerDispatcher},
    http::HTTPStreamEvent,
    key_db::KeyDB,
    listener::{Listener, MessageMeta, SideData, TimingInfo},
    tcp_reassemble::TcpFollower,
    tls::TLSFlowTracker,
};

pub static NYA_DSB: &'static [u8] = include_bytes!("../corpus/nya-dsb.pcapng");
pub static H1_CONN_REUSE: &'static [u8] = include_bytes!("../corpus/http-conn-reuse.pcapng");
pub static H2: &'static [u8] = include_bytes!("../corpus/http2-conn-reuse.pcapng");
pub static H2_BIG_HEADERS: &'static [u8] = include_bytes!("../corpus/http2-big-headers.pcapng");
pub static TLS13_SESSION_RESUMPTION: &'static [u8] =
    include_bytes!("../corpus/tls13-session-resumption.pcapng");
pub static H1_UNENCRYPTED: &'static [u8] = include_bytes!("../corpus/http-80.pcapng");

pub enum Received<T> {
    Message(MessageMeta, T),
    SideData(Box<dyn SideData>),
}

impl fmt::Display for Received<Vec<u8>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Received::Message(_meta, d) => write!(f, "Message:\n{}", hexdump::HexDumper::new(&d)),
            Received::SideData(sd) => write!(f, "Side data:\n{:?}", sd),
        }
    }
}

impl fmt::Display for Received<HTTPStreamEvent> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Received::Message(_meta, d) => {
                write!(f, "Message:\n{:?}", d)?;
                match d {
                    HTTPStreamEvent::ReqBodyChunk(_id, d) => {
                        write!(f, "\n{}", hexdump::HexDumper::new(d))?
                    }
                    HTTPStreamEvent::RespBodyChunk(_id, d) => {
                        write!(f, "\n{}", hexdump::HexDumper::new(d))?
                    }
                    _ => {}
                };
                Ok(())
            }
            Received::SideData(sd) => write!(f, "Side data:\n{:?}", sd),
        }
    }
}

pub struct TestListener<T> {
    pub received: Arc<RwLock<Vec<Received<T>>>>,
}

impl<T: Send + Sync> Listener<T> for TestListener<T> {
    fn on_data(
        &mut self,
        timing: crate::listener::TimingInfo,
        target: crate::chomp::IPTarget,
        to_client: bool,
        data: T,
    ) {
        self.received.write().unwrap().push(Received::Message(
            MessageMeta {
                timing,
                target,
                to_client,
            },
            data,
        ))
    }

    fn on_side_data(&mut self, data: Box<dyn SideData>) {
        // We need to deduplicate the inputs we get from the stack, since side
        // data is duplicated when it is sent to the downstream consumers of a
        // join.
        //
        // XXX: this is trash deduplication code lmao
        // I think that we should replace it with some code in `listener` which
        // auto implements a method which uses Any to implement a boxed
        // comparison that dispatches to concrete Eq/PartialEq instances.
        let mut g = self.received.write().unwrap();
        let last = g.last().and_then(|v| match v {
            Received::SideData(s) => Some(format!("{s:?}")),
            _ => None,
        });

        if let Some(last) = last {
            let v = format!("{:?}", &data);

            if v == last {
                return;
            }
            g.push(Received::SideData(data));
        } else {
            g.push(Received::SideData(data));
        }
    }
}

#[derive(Default)]
pub struct KeyMessageReorderer {
    packets: Vec<(TimingInfo, Vec<u8>)>,
    keys: Vec<Vec<u8>>,
}

impl FrameChomper for KeyMessageReorderer {
    fn chomp(&mut self, timing: TimingInfo, packet: &[u8]) -> Result<(), crate::Error> {
        self.packets.push((timing, packet.to_vec()));
        Ok(())
    }

    fn on_keys(&mut self, dsb: &[u8]) {
        self.keys.push(dsb.to_vec());
    }

    fn on_key(
        &mut self,
        _client_random: crate::key_db::ClientRandom,
        _secret_type: crate::key_db::SecretType,
        _secret: crate::key_db::Secret,
    ) {
        unimplemented!()
    }
}

impl KeyMessageReorderer {
    #[allow(unused)]
    pub fn send(&self, recv: &mut impl FrameChomper) -> Result<(), crate::Error> {
        for key in &self.keys {
            recv.on_keys(&key)
        }

        for (timing, pkt) in &self.packets {
            recv.chomp(timing.clone(), &pkt)?;
        }
        Ok(())
    }

    pub fn send_late_keys(&self, recv: &mut impl FrameChomper) -> Result<(), crate::Error> {
        for (timing, pkt) in &self.packets {
            recv.chomp(timing.clone(), &pkt)?;
        }

        for key in &self.keys {
            recv.on_keys(&key)
        }

        Ok(())
    }
}

pub fn check<T>(expected: expect_test::ExpectFile, received: &[Received<T>])
where
    Received<T>: fmt::Display,
{
    let mut actual = String::new();
    for recvd in received.iter() {
        writeln!(&mut actual, "{recvd}\n").unwrap();
    }

    expected.assert_eq(&actual);
}

pub fn raw_chomper<Recv: Listener<Vec<u8>>>(
    key_db: Arc<RwLock<KeyDB>>,
    recv: Recv,
) -> EthernetChomper<Recv> {
    EthernetChomper {
        tcp_follower: TcpFollower::default(),
        recv,
        key_db: key_db.clone(),
    }
}

pub fn tls_chomper(
    key_db: Arc<RwLock<KeyDB>>,
    received: Arc<RwLock<Vec<Received<Vec<u8>>>>>,
) -> EthernetChomper<TLSFlowTracker> {
    raw_chomper(
        key_db.clone(),
        TLSFlowTracker::new(key_db, Box::new(TestListener { received })),
    )
}

pub fn tls_chomper_dispatch(
    key_db: Arc<RwLock<KeyDB>>,
    received: Arc<RwLock<Vec<Received<Vec<u8>>>>>,
) -> EthernetChomper<ListenerDispatcher> {
    let dispatch = dispatch::ListenerDispatcher::default().add(
        443,
        TLSFlowTracker::new(key_db.clone(), Box::new(TestListener { received })),
    );

    raw_chomper(key_db, dispatch)
}

pub fn http_chomper(
    key_db: Arc<RwLock<KeyDB>>,
    received: Arc<RwLock<Vec<Received<HTTPStreamEvent>>>>,
) -> EthernetChomper<ListenerDispatcher> {
    chomper(TestListener { received }, key_db)
}
