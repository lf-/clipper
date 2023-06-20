// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use std::{
    any::{Any, TypeId},
    collections::BTreeMap,
    fmt,
};

use crate::chomp::IPTarget;

/// Simple type indexed map
#[derive(Default, Debug, Clone)]
pub struct TypeMap<V>(BTreeMap<TypeId, V>);

impl<V> TypeMap<V> {
    pub fn get<T: Any>(&self) -> Option<&V> {
        self.0.get(&TypeId::of::<T>())
    }

    pub fn insert<T: Any>(&mut self, val: V) {
        self.0.insert(TypeId::of::<T>(), val);
    }
}

/// Nanoseconds since the Unix epoch
pub type Nanos = u64;

#[derive(Clone, Debug, Default)]
pub struct TimingInfo {
    pub received_on_wire: Nanos,
    // Debating whether to put this in individual modules or have a central
    // registry. I would like to not have a central registry to make this code
    // more reusable.
    pub other_times: TypeMap<Nanos>,
}

/// Type which receives some kind of messages from a layer up the stack.
///
/// The `target` is the same in both directions so a flow can be tracked.
pub trait Listener<MessageType> {
    fn on_data(&mut self, timing: TimingInfo, target: IPTarget, to_client: bool, data: MessageType);
}

#[derive(Debug, Default)]
pub struct NoOpListener {}

impl<T> Listener<T> for NoOpListener {
    fn on_data(&mut self, _timing: TimingInfo, _target: IPTarget, _to_client: bool, _data: T) {
        // do nothing! :D
    }
}

#[derive(Debug, Default)]
pub struct HexDumpListener {}

impl Listener<Vec<u8>> for HexDumpListener {
    fn on_data(&mut self, _timing: TimingInfo, target: IPTarget, to_client: bool, data: Vec<u8>) {
        tracing::info!(
            "data {target:?} to_client={to_client}:\n{}",
            hexdump::HexDumper::new(&data)
        );
    }
}

#[derive(Debug, Default)]
pub struct DebugListener {}

impl<T: fmt::Debug> Listener<T> for DebugListener {
    fn on_data(&mut self, _timing: TimingInfo, target: IPTarget, to_client: bool, data: T) {
        tracing::info!("data {target:?} to_client={to_client}: {data:?}");
    }
}
