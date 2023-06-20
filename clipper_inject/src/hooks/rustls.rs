// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! Hooks to extract keys from rustls.
//!
//! These are extremely crimey because rustls is statically linked into the
//! executable images, and we would prefer to be ABI compatible with as many
//! versions of rustls as possible, including multiple instances of it in the
//! same executable.
//!
//! This might wind up backfiring on us if they ever wind up changing the
//! signatures of the KeyLog trait (I don't know how we can find what version a
//! rustls instance is with just an executable).
//!
//! It's easier to patch the existing NoKeyLog implementation than to try to
//! create our own KeyLog instance, since we would (1) like to avoid linking to
//! the crate and (2) it's kind of hard to actually set the field, since the
//! ABI of ClientConfig and friends are (totally reasonably) not going to be
//! stable.

use frida_gum::NativePointer;
use libc::c_void;

use crate::{hooks::find_demangled_symbol, log_target::LOG_TARGET};

use super::{applicability, ApplicabilityContext, Hooks};

use std::marker::FnPtr;

pub struct RustlsHooks {}

const WILL_LOG_SYM: &'static str =
    "<rustls::key_log::NoKeyLog as rustls::key_log::KeyLog>::will_log";
const LOG_SYM: &'static str = "<rustls::key_log::NoKeyLog as rustls::key_log::KeyLog>::log";

pub trait CrimeKeyLog: Send + Sync {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);

    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

/// NOTE: this cannot have any members since what this *actually* is is
/// a `rustls::NoKeyLog`
struct MyShirtWhichSaysNoKeyLog {}

impl CrimeKeyLog for MyShirtWhichSaysNoKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        LOG_TARGET.get().unwrap().log(label, client_random, secret);
    }

    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

type LogTy = for<'a, 'b, 'c, 'd> fn(&'a MyShirtWhichSaysNoKeyLog, &'b str, &'c [u8], &'d [u8]);
type WillLogTy = for<'a, 'b> fn(&'a MyShirtWhichSaysNoKeyLog, &'b str) -> bool;

impl Hooks for RustlsHooks {
    fn applicability(&self) -> &'static dyn super::HookApplicability {
        &applicability::SymbolPresent {
            name: WILL_LOG_SYM,
            demangled: true,
        }
    }

    fn name(&self) -> &'static str {
        "rustls"
    }

    unsafe fn apply(
        &self,
        hook_service: &mut super::HookService,
        context: ApplicabilityContext<'_>,
    ) {
        let log_addr = find_demangled_symbol(context.main_symbols, LOG_SYM).map(|s| s.address);

        let will_log_addr =
            find_demangled_symbol(context.main_symbols, WILL_LOG_SYM).map(|s| s.address);

        let (log_addr, will_log_addr) =
            if let Some((log_addr, will_log_addr)) = log_addr.zip(will_log_addr) {
                (log_addr, will_log_addr)
            } else {
                return;
            };

        hook_service
            .raw_hook(
                NativePointer(log_addr as *mut c_void),
                NativePointer((MyShirtWhichSaysNoKeyLog::log as LogTy).addr() as *mut c_void),
            )
            .unwrap();

        hook_service
            .raw_hook(
                NativePointer(will_log_addr as *mut c_void),
                NativePointer(
                    (MyShirtWhichSaysNoKeyLog::will_log as WillLogTy).addr() as *mut c_void
                ),
            )
            .unwrap();

        tracing::debug!("log_func: {log_addr:x?}, will_log: {will_log_addr:x?}");
    }
}
