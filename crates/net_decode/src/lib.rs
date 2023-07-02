// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

pub mod chomp;
pub mod http;
pub mod key_db;
pub mod listener;
pub mod tcp_reassemble;
#[cfg(test)]
mod test_support;
pub mod tls;

type Error = Box<dyn std::error::Error + Send + Sync>;
