// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! hooking dlopen for fun and profit (to catch loads of tls libraries after
//! program startup, such as with Python)

use std::{
    ffi::{c_char, c_int, CStr},
    os::raw::c_void,
};

use libc::RTLD_NOLOAD;

use super::{applicability, Hooks, LibItem};

type Dlopen = extern "C" fn(fname: *const c_char, flags: c_int) -> *mut c_void;

static DLOPEN: LibItem<Dlopen> = LibItem::new_no_module("dlopen");

extern "C" fn dlopen_detour(fname: *const c_char, flags: c_int) -> *mut c_void {
    let r = (DLOPEN.orig.get().unwrap())(fname, flags);

    tracing::debug!(file = ?unsafe { CStr::from_ptr(fname) }, "dlopen");

    // RTLD_NOLOAD is used internally inside frida_gum, which causes a really
    // funny deadlock; we don't ever need to rerun hooks on it anyway, since by
    // definition the loaded libs won't have changed.
    if flags & RTLD_NOLOAD == 0 {
        let mut svc = super::HOOK_SERVICE.get().unwrap().lock().unwrap();
        unsafe { svc.init_hooks() };
    }

    r
}

pub struct DlopenHook;

impl Hooks for DlopenHook {
    fn name(&self) -> &'static str {
        "dlopen"
    }

    unsafe fn apply(
        &self,
        hook_service: &mut super::HookService,
        _context: super::ApplicabilityContext<'_>,
    ) {
        hook_service.hook_export(&DLOPEN, dlopen_detour).unwrap();
    }

    fn applicability(&self) -> &'static dyn super::HookApplicability {
        &applicability::AlwaysApplicable {}
    }
}
