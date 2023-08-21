// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! We export a library so that we can test it through dlopen also.
mod contents;

pub use contents::*;
