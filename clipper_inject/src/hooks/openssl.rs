//! Hooks to pull keys out of openssl

use std::ffi::{c_char, CStr};

use super::{HookApplicability, HookService, Hooks, LibItem};

#[repr(transparent)]
#[derive(Clone, Copy)]
struct SSL(*mut ());

#[repr(transparent)]
#[derive(Clone, Copy)]
struct SSL_CTX(*mut ());

type SSL_CTX_keylog_cb_func = unsafe extern "C" fn(SSL, *const c_char);

// FIXME: we need to be able to disregard sonames for this purpose, which
// involves not inputting the libssl.so.3 name here. this needs to be passed in
// from elsewhere

static SSL_new: LibItem<unsafe extern "C" fn(SSL_CTX) -> SSL> =
    LibItem::new("libssl.so.3", "SSL_new");
static SSL_CTX_set_keylog_callback: LibItem<unsafe extern "C" fn(SSL_CTX, SSL_CTX_keylog_cb_func)> =
    LibItem::new("libssl.so.3", "SSL_CTX_set_keylog_callback");

unsafe extern "C" fn keylog_callback(_ssl: SSL, s: *const c_char) {
    let s = unsafe { CStr::from_ptr(s) };
    eprintln!("nya!! {s:?}");
}

unsafe extern "C" fn SSL_new_wrap(ctx: SSL_CTX) -> SSL {
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    SSL_new(ctx)
}

pub struct OpenSSLHooks {}

impl Hooks for OpenSSLHooks {
    fn applicability(&self) -> &'static dyn HookApplicability {
        &super::applicability::LibName("ssl")
    }

    fn name(&self) -> &'static str {
        "openssl"
    }

    unsafe fn apply(&self, hook_service: &mut HookService) {
        hook_service
            .find_export(&SSL_CTX_set_keylog_callback)
            .unwrap();
        hook_service
            .hook_export(&SSL_new, SSL_new_wrap as _)
            .unwrap();
    }
}
