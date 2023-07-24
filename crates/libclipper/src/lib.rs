// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

#[cfg(target_os = "linux")]
pub mod capture;
pub mod devtools;

pub const APP_IDENTIFICATION: &'static str = concat!("clipper ", env!("CARGO_PKG_VERSION"));

#[cfg(target_os = "linux")]
pub const CLIPPER_INJECT_DYLIB_NAME: &'static str = "libclipper_inject.so";

pub type Error = Box<dyn std::error::Error + Send + Sync>;
