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
    http::{HTTPRequestTracker, HTTPStreamEvent},
    key_db::KeyDB,
    listener::{Listener, MessageMeta, SideData, TimingInfo},
    tcp_reassemble::TcpFollower,
    tls::TLSFlowTracker,
};

pub static NYA_DSB: &'static [u8] = include_bytes!("../corpus/nya-dsb.pcapng");
pub static H2: &'static [u8] = include_bytes!("../corpus/http2-conn-reuse.pcapng");

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
        self.received
            .write()
            .unwrap()
            .push(Received::SideData(data))
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

pub fn tls_chomper(
    key_db: Arc<RwLock<KeyDB>>,
    received: Arc<RwLock<Vec<Received<Vec<u8>>>>>,
) -> EthernetChomper<TLSFlowTracker> {
    EthernetChomper {
        tcp_follower: TcpFollower::default(),
        recv: TLSFlowTracker::new(key_db.clone(), Box::new(TestListener { received })),
        key_db: key_db.clone(),
    }
}

pub fn http_chomper(
    key_db: Arc<RwLock<KeyDB>>,
    received: Arc<RwLock<Vec<Received<HTTPStreamEvent>>>>,
) -> EthernetChomper<TLSFlowTracker> {
    EthernetChomper {
        tcp_follower: TcpFollower::default(),
        recv: TLSFlowTracker::new(
            key_db.clone(),
            Box::new(HTTPRequestTracker::new(Box::new(TestListener { received }))),
        ),
        key_db: key_db.clone(),
    }
}
