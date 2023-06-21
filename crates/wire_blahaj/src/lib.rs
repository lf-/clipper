// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Wire shark doo doo doo doo doo doo
//!
//! Packet capture functionality for clipper.

use nix::sys::time::TimeSpec;

#[cfg(target_os = "linux")]
pub mod unprivileged;

pub mod pcap_writer;

/// Nanoseconds since the Unix epoch
pub type Nanos = u64;

pub fn ts_to_nanos(ts: TimeSpec) -> Nanos {
    (ts.tv_sec() as u64) * 10u64.pow(9) + (ts.tv_nsec() as u64)
}
