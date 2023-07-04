#![feature(fn_ptr_trait)]
#![feature(lazy_cell)]
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use std::{fs::OpenOptions, ops::Deref};

use frida_gum::Module;
use log_target::LogTarget;

use crate::{
    hooks::{init_hooks, HookService, GUM},
    log_target::{LogTargetRpc, LogTargetStream, LOG_TARGET},
};
use tracing_subscriber::{fmt, prelude::*};

mod hooks;
mod log_target;
mod rpc;

fn pick_target() -> Box<dyn LogTarget> {
    match std::env::var(clipper_protocol::SOCKET_ENV_VAR) {
        Ok(v) => Box::new(LogTargetRpc::new(v.into())),
        Err(_) => match std::env::var("SSLKEYLOGFILE") {
            Ok(v) => Box::new(LogTargetStream::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(v)
                    .expect("opening SSLKEYLOGFILE"),
            )),
            Err(_) => Box::new(LogTargetStream::new(std::io::stderr())),
        },
    }
}

#[ctor::ctor]
unsafe fn init() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_env("CLIPPER_LOG"))
        .init();

    tracing::debug!("nyanyanyanya");
    let _ = GUM.deref();
    let modules = Module::enumerate_modules();
    for md in modules {
        tracing::debug!(
            "name={:?} path={:?} base={:x?}",
            &md.name,
            &md.path,
            &md.base_address
        );
    }

    let _ = LOG_TARGET.set(pick_target());

    let mut hook_service = HookService::new();
    init_hooks(&mut hook_service);
}
