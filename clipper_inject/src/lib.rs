#![feature(fn_ptr_trait)]
#![feature(lazy_cell)]
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use std::ops::Deref;

use frida_gum::Module;

use crate::{
    hooks::{init_hooks, HookService, GUM},
    log_target::{LogTargetStdout, LOG_TARGET},
};
use tracing_subscriber::{fmt, prelude::*};

mod hooks;
mod log_target;
mod preload;

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

    let _ = LOG_TARGET.set(Box::new(LogTargetStdout {}));

    let mut hook_service = HookService::new();
    init_hooks(&mut hook_service);
}
