// SPDX-FileCopyrightText: Rustls Contributors, Jade Lovelace
// SPDX-License-Identifier: MIT OR Apache-2.0 OR ISC
//! Decoding of TLS, fun!
//!
//! It's 50/50 on hacking the shit out of rustls or figuring out how to use
//! tls-parser, and I think that hacking the shit out of rustls is possibly the
//! way to get least surprised.

use std::collections::{HashMap, VecDeque};

use rustls_intercept::{
    internal::{
        msgs::{
            deframer::{Deframed, MessageDeframer},
            message::{Message, PlainMessage},
        },
        record_layer::RecordLayer,
    },
    server::Accepted,
};

use crate::{chomp::IPTarget, tcp_reassemble::TCPFlowReceiver};

pub struct TLSFlow {
    record_layer: RecordLayer,
    deframer: MessageDeframer,

    /// Buffer used to manage force feeding rustls with data (since it expects
    /// to drive the feeding process rather than be fed data).
    client_read_buffer: VecDeque<u8>,
}

impl Default for TLSFlow {
    fn default() -> Self {
        Self {
            record_layer: RecordLayer::new(),
            deframer: MessageDeframer::default(),
            client_read_buffer: Default::default(),
        }
    }
}

impl TLSFlow {
    // Relatively similar to ConnectionCore::deframe, but does not send alerts
    // TODO: should we just concede and implement ConnectionCore and just not
    // send data back???
    fn deframe(&mut self) -> Result<Option<PlainMessage>, rustls_intercept::Error> {
        match self.deframer.pop(&mut self.record_layer) {
            Ok(Some(Deframed {
                message,
                trial_decryption_finished,
                ..
            })) => {
                if trial_decryption_finished {
                    self.record_layer.finish_trial_decryption();
                }
                Ok(Some(message))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Default)]
pub struct TLSFlowTracker {
    flows: HashMap<IPTarget, TLSFlow>,
}

fn is_tls(target: &IPTarget) -> bool {
    target.server_port() == 443
}

impl TCPFlowReceiver for TLSFlowTracker {
    fn on_data(&mut self, target: IPTarget, to_client: bool, data: Vec<u8>) {
        if !is_tls(&target) {
            return;
        }

        let entry = self.flows.entry(target).or_insert_with(Default::default);

        if to_client {
            entry.client_read_buffer.extend(&data);
            entry.deframer.read(&mut entry.client_read_buffer).unwrap();
            let msg = entry.deframe();
            // tracing::debug!("deframed: {:?}", msg);
            if let Ok(Some(v)) = msg {
                let msg = Message::try_from(v);
                if let Ok(msg) = msg {
                    tracing::debug!("msg: {:?}", &msg);
                    // let hello = Accepted::client_hello_payload(&msg);
                }
            }
        }
    }
}
