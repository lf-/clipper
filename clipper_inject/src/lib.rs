#![feature(fn_ptr_trait)]
#![feature(lazy_cell)]
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use std::ops::Deref;

use frida_gum::Module;

use crate::hooks::{init_hooks, HookService, GUM};

mod hooks;
mod preload;

#[ctor::ctor]
unsafe fn init() {
    eprintln!("nya1!");
    let _ = GUM.deref();
    let modules = Module::enumerate_modules();
    for md in modules {
        eprintln!(
            "name={:?} path={:?} base={:x?}",
            &md.name, &md.path, &md.base_address
        );
    }

    let mut hook_service = HookService::new();
    init_hooks(&mut hook_service);
    eprintln!("nya!");
}
