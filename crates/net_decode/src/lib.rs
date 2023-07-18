// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use std::sync::{Arc, RwLock};

use chomp::EthernetChomper;
use dispatch::ListenerDispatcher;
use http::{HTTPRequestTracker, HTTPStreamEvent};
use key_db::KeyDB;
use listener::Listener;
use tcp_reassemble::TcpFollower;
use tls::TLSFlowTracker;

pub mod chomp;
pub mod dispatch;
pub mod http;
pub mod key_db;
pub mod listener;
pub mod tcp_reassemble;
#[cfg(test)]
mod test_support;
pub mod tls;

type Error = Box<dyn std::error::Error + Send + Sync>;

pub fn chomper<L: Listener<HTTPStreamEvent> + 'static>(
    http_listener: L,
    key_db: Arc<RwLock<KeyDB>>,
) -> EthernetChomper<ListenerDispatcher> {
    let join = dispatch::ListenerJoin::new(http_listener);
    let dispatch = dispatch::ListenerDispatcher::default()
        .add(80, HTTPRequestTracker::new(Box::new(join.clone())))
        .add(
            443,
            TLSFlowTracker::new(
                key_db.clone(),
                Box::new(HTTPRequestTracker::new(Box::new(join))),
            ),
        );

    EthernetChomper {
        tcp_follower: TcpFollower::default(),
        recv: dispatch,
        key_db,
    }
}
