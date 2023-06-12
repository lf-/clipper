//! Decoding of TLS, fun!
//!
//! It's 50/50 on hacking the shit out of rustls or figuring out how to use
//! tls-parser, and I think that hacking the shit out of rustls is possibly the
//! way to get least surprised.

use std::collections::{HashMap, VecDeque};

use rustls_intercept::internal::{msgs::deframer::MessageDeframer, record_layer::RecordLayer};

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
            let msg = entry.deframer.pop(&mut entry.record_layer);
            tracing::debug!("deframed: {:?}", msg);
        }
    }
}
