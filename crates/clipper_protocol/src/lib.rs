// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

pub mod proto {
    pub mod embedding {
        include!(concat!(env!("OUT_DIR"), "/clipper.embedding.rs"));
    }
}
