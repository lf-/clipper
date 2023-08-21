// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! This module uses Frida's gum library for injection into functions. This is
//! necessary to do things like intercepting functions with more force, for
//! example, private functions or functions that are not accessed via exports.
//!
//! Such a mechanism of use of more forceful code injection avoids some of the
//! potential issues with just using LD_PRELOAD by itself, which requires that
//! the interesting function in question is using dynamic binding, which
//! cannot be assumed.

mod dlopen;
mod openssl;
mod rustls;

use std::{
    collections::HashSet,
    fmt::Write,
    marker::FnPtr,
    mem, ptr,
    sync::{LazyLock, Mutex, OnceLock},
};

use frida_gum::{
    interceptor::Interceptor, Gum, Module, ModuleDetailsOwned, NativePointer, SymbolDetails,
};
use lazy_static::lazy_static;
use libc::c_void;
use regex::Regex;

pub static GUM: LazyLock<Gum> = LazyLock::new(|| unsafe { Gum::obtain() });
pub static HOOK_SERVICE: OnceLock<Mutex<HookService<'static>>> = OnceLock::new();

pub struct LibItem<TFun: FnPtr> {
    module_name: Option<&'static str>,
    fun_name: &'static str,
    orig: OnceLock<TFun>,
}

impl<TFun: FnPtr> LibItem<TFun> {
    pub const fn new(module_name: &'static str, fun_name: &'static str) -> LibItem<TFun> {
        LibItem {
            module_name: Some(module_name),
            fun_name,
            orig: OnceLock::new(),
        }
    }
    pub const fn new_no_module(fun_name: &'static str) -> LibItem<TFun> {
        LibItem {
            module_name: None,
            fun_name,
            orig: OnceLock::new(),
        }
    }
}

impl<TFun: FnPtr> std::ops::Deref for LibItem<TFun> {
    type Target = TFun;
    fn deref(&self) -> &Self::Target {
        self.orig.get().expect("Orig missing")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("Could not find export")]
    CouldNotFindExport,
    #[error("Frida failed: {0}")]
    FridaError(frida_gum::Error),
}

// Since thiserror assumes that if you use #[from], the inner value is
// std::error::Error, we have to write this manually.
impl From<frida_gum::Error> for HookError {
    fn from(value: frida_gum::Error) -> Self {
        HookError::FridaError(value)
    }
}

pub struct HookService<'a> {
    applied: HashSet<&'static str>,
    interceptor: Interceptor<'a>,
}

// SAFETY: honestly I don't know for sure if it's Send, but the internals
// suggest it's Sync by itself. We will stick it in a mutex because whatever.
unsafe impl<'a> Send for HookService<'a> {}

unsafe fn transmute_same_size<T: Copy, U>(val: T) -> U {
    assert_eq!(mem::size_of::<T>(), mem::size_of::<U>());
    let val2: U = std::mem::transmute_copy(&val);
    val2
}

impl<'a> HookService<'a> {
    pub unsafe fn new() -> HookService<'static> {
        HookService {
            applied: Default::default(),
            interceptor: Interceptor::obtain(&GUM),
        }
    }

    /// Finds an export and puts it into the LibItem provided without applying
    /// a hook.
    pub unsafe fn find_export<TFun: FnPtr>(
        &mut self,
        item: &LibItem<TFun>,
    ) -> Result<(), HookError> {
        let export = Module::find_export_by_name(item.module_name, item.fun_name)
            .ok_or(HookError::CouldNotFindExport)?;

        let export: TFun = transmute_same_size(export);
        let _ = item.orig.set(export);

        Ok(())
    }

    /// Finds an export, hooks it to the provided function, then puts it into
    /// the LibItem provided.
    pub unsafe fn hook_export<TFun: FnPtr>(
        &mut self,
        hook: &LibItem<TFun>,
        ptr: TFun,
    ) -> Result<(), HookError> {
        let export = Module::find_export_by_name(hook.module_name, hook.fun_name)
            .ok_or(HookError::CouldNotFindExport)?;

        tracing::debug!("hook {:?} -> {:?}", export.0, ptr.addr());
        let orig = self.interceptor.replace(
            export,
            NativePointer(ptr.addr() as *mut c_void),
            NativePointer(ptr::null_mut()),
        )?;

        let orig: TFun = transmute_same_size(orig);

        let _ = hook.orig.set(orig);

        Ok(())
    }

    pub unsafe fn raw_hook(
        &mut self,
        fun: NativePointer,
        redirect_to: NativePointer,
    ) -> Result<NativePointer, HookError> {
        tracing::debug!("hook {:x?} -> {:x?}", fun.0, redirect_to.0);
        Ok(self
            .interceptor
            .replace(fun, redirect_to, NativePointer(ptr::null_mut()))?)
    }

    pub unsafe fn init_hooks(&mut self) {
        // FIXME: list of disabled hooks

        let mod_list = Module::enumerate_modules();
        let libnames = mod_list
            .iter()
            .filter_map(|m| to_libname(&m.name).map(|v| v.to_string()))
            .collect::<HashSet<String>>();
        let main_symbols = Module::enumerate_symbols(&mod_list[0].name);

        let applicability_context = ApplicabilityContext {
            lib_names: &libnames,
            modules: &mod_list,
            main_symbols: &main_symbols,
        };

        for &hook in HOOKS {
            let name = hook.name();
            if self.applied.contains(name) {
                tracing::debug!("already applied: {}", name);
                continue;
            }

            tracing::debug!("checking if we should load hook {}", name);
            if hook
                .applicability()
                .is_applicable(applicability_context.clone())
            {
                tracing::debug!("apply hook {}", name);
                unsafe { hook.apply(self, applicability_context.clone()) };
                self.applied.insert(name);
            }
        }
        tracing::debug!("hooks done");
    }
}

/// Context for checking for applicability
#[derive(Clone)]
pub struct ApplicabilityContext<'a> {
    pub lib_names: &'a HashSet<String>,
    pub modules: &'a [ModuleDetailsOwned],
    pub main_symbols: &'a [SymbolDetails],
}

pub trait HookApplicability {
    fn is_applicable(&self, context: ApplicabilityContext<'_>) -> bool;
}

fn find_demangled_symbol<'a>(syms: &'a [SymbolDetails], name: &str) -> Option<&'a SymbolDetails> {
    let mut buf = String::new();
    syms.iter().find(|s| {
        buf.clear();
        write!(&mut buf, "{:#}", rustc_demangle::demangle(&s.name)).unwrap();
        &buf == name
    })
}

mod applicability {
    use frida_gum::Module;

    use super::{find_demangled_symbol, ApplicabilityContext, HookApplicability};

    /// For e.g. `libssl.so.3`, this would be `libssl`.
    pub struct LibName(pub &'static str);

    /// Checks if a given symbol is present in the main image.
    ///
    /// Useful for statically linked libraries, if we have symbols available
    /// (sometimes we do...).
    pub struct SymbolPresent {
        pub name: &'static str,
        pub demangled: bool,
    }

    impl HookApplicability for LibName {
        fn is_applicable(&self, context: ApplicabilityContext<'_>) -> bool {
            context.lib_names.contains(self.0)
        }
    }

    impl HookApplicability for SymbolPresent {
        fn is_applicable(&self, context: ApplicabilityContext<'_>) -> bool {
            let main_module = &context.modules[0];

            // Can't do much about this, we have to demangle the thing and find
            // it in the list. It's gonna be O(n).
            if self.demangled {
                find_demangled_symbol(&context.main_symbols, self.name).is_some()
            } else {
                Module::find_symbol_by_name(&main_module.name, self.name).is_some()
            }
        }
    }

    pub struct AlwaysApplicable {}

    impl HookApplicability for AlwaysApplicable {
        fn is_applicable(&self, _context: ApplicabilityContext<'_>) -> bool {
            true
        }
    }
}

/// One library's hooks
pub trait Hooks: Send + Sync {
    /// When the hook should have apply() called.
    fn applicability(&self) -> &'static dyn HookApplicability;

    /// Name used for disabling this particular hook
    fn name(&self) -> &'static str;

    /// Applies the hook
    unsafe fn apply(&self, hook_service: &mut HookService, context: ApplicabilityContext<'_>);
}

fn to_libname(name: &str) -> Option<&str> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"^lib(.*)\.so(\.\d+)*$"#).unwrap();
    }

    let inside = RE.captures(name)?.get(1)?;
    Some(inside.as_str())
}

static HOOKS: &[&dyn Hooks] = &[
    &dlopen::DlopenHook,
    &openssl::OpenSSLHooks {},
    &rustls::RustlsHooks {},
];
