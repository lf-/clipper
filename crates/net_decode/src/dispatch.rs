// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Dispatch to the correct decoder.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use crate::{chomp::IPTarget, listener::Listener};

trait ErasedMatcher: Matcher + fmt::Debug + Send + Sync + 'static {}

impl<T: Matcher + fmt::Debug + Send + Sync + 'static> ErasedMatcher for T {}

pub trait Matcher {
    fn match_traffic(&self, target: IPTarget) -> bool;
    fn as_debug(&self) -> &dyn fmt::Debug;
}

impl Matcher for u16 {
    fn match_traffic(&self, target: IPTarget) -> bool {
        target.server_port() == *self
    }
    fn as_debug(&self) -> &dyn fmt::Debug {
        self
    }
}

impl<F> Matcher for F
where
    F: Fn(IPTarget) -> bool,
{
    fn match_traffic(&self, target: IPTarget) -> bool {
        self(target)
    }

    fn as_debug(&self) -> &dyn fmt::Debug {
        &"(closure)"
    }
}

type ErasedBytesListener = Box<dyn Listener<Vec<u8>> + Send + Sync + 'static>;

#[derive(Default)]
pub struct ListenerDispatcher {
    listeners: Vec<(Box<dyn ErasedMatcher>, ErasedBytesListener)>,
}

impl ListenerDispatcher {
    pub fn add(
        mut self,
        m: impl Matcher + fmt::Debug + Send + Sync + 'static,
        listener: impl Listener<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        self.listeners.push((Box::new(m), Box::new(listener)));
        self
    }
}

impl Listener<Vec<u8>> for ListenerDispatcher {
    fn on_data(
        &mut self,
        timing: crate::listener::TimingInfo,
        target: IPTarget,
        to_client: bool,
        data: Vec<u8>,
    ) {
        for (m, l) in &mut self.listeners {
            tracing::trace!(rule = ?m.as_debug(), "try rule");
            if m.match_traffic(target) {
                tracing::trace!(rule = ?m.as_debug(), "match rule");
                l.on_data(timing, target, to_client, data);
                return;
            }
        }
    }

    fn on_side_data(&mut self, data: Box<dyn crate::listener::SideData>) {
        for (_m, l) in &mut self.listeners {
            l.on_side_data(dyn_clone::clone_box(&data))
        }
    }
}

pub struct ListenerJoin<T> {
    inner: Arc<Mutex<Box<dyn Listener<T>>>>,
}

impl<T> ListenerJoin<T> {
    pub fn new<L: Listener<T> + 'static>(inner: L) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::new(inner))),
        }
    }
}

impl<T> Clone for ListenerJoin<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Listener<T> for ListenerJoin<T> {
    fn on_data(
        &mut self,
        timing: crate::listener::TimingInfo,
        target: IPTarget,
        to_client: bool,
        data: T,
    ) {
        let mut g = self.inner.lock().unwrap();
        g.on_data(timing, target, to_client, data);
    }

    fn on_side_data(&mut self, data: Box<dyn crate::listener::SideData>) {
        let mut g = self.inner.lock().unwrap();
        g.on_side_data(data);
    }
}
