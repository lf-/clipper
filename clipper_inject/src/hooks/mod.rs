//! This module uses Frida's gum library for injection into functions. This is
//! necessary to do things like intercepting functions with more force, for
//! example, private functions or functions that are not accessed via exports.
//!
//! Such a mechanism of use of more forceful code injection avoids some of the
//! potential issues with just using LD_PRELOAD by itself, which requires that
//! the interesting function in question is using dynamic binding, which
//! cannot be assumed.

mod openssl;

use std::{
    collections::HashSet,
    marker::FnPtr,
    mem, ptr,
    sync::{LazyLock, OnceLock},
};

use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use libc::c_void;
use regex::Regex;

pub static GUM: LazyLock<Gum> = LazyLock::new(|| unsafe { Gum::obtain() });

pub struct LibItem<TFun: FnPtr> {
    module_name: &'static str,
    fun_name: &'static str,
    orig: OnceLock<TFun>,
}

impl<TFun: FnPtr> LibItem<TFun> {
    pub const fn new(module_name: &'static str, fun_name: &'static str) -> LibItem<TFun> {
        LibItem {
            module_name,
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
    interceptor: Interceptor<'a>,
}

unsafe fn transmute_same_size<T: Copy, U>(val: T) -> U {
    assert_eq!(mem::size_of::<T>(), mem::size_of::<U>());
    let val2: U = std::mem::transmute_copy(&val);
    val2
}

impl<'a> HookService<'a> {
    pub unsafe fn new() -> HookService<'static> {
        HookService {
            interceptor: Interceptor::obtain(&GUM),
        }
    }

    /// Finds an export and puts it into the LibItem provided without applying
    /// a hook.
    pub unsafe fn find_export<TFun: FnPtr>(
        &mut self,
        item: &LibItem<TFun>,
    ) -> Result<(), HookError> {
        let export = Module::find_export_by_name(Some(item.module_name), item.fun_name)
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
        let export = Module::find_export_by_name(Some(hook.module_name), hook.fun_name)
            .ok_or(HookError::CouldNotFindExport)?;

        let orig = self.interceptor.replace(
            export,
            NativePointer(ptr.addr() as *mut c_void),
            NativePointer(ptr::null_mut()),
        )?;

        let orig: TFun = transmute_same_size(orig);

        let _ = hook.orig.set(orig);

        Ok(())
    }
}

pub trait HookApplicability {
    fn is_applicable(&self, lib_names: &HashSet<String>) -> bool;
}

mod applicability {
    use std::collections::HashSet;

    use super::HookApplicability;

    /// For e.g. `libssl.so.3`, this would be `libssl`.
    pub struct LibName(pub &'static str);

    /// Checks if a given symbol is present in the main image.
    ///
    /// Useful for statically linked libraries, if we have symbols available
    /// (sometimes we do...).
    pub struct SymbolPresent(pub &'static str);

    impl HookApplicability for LibName {
        fn is_applicable(&self, lib_names: &HashSet<String>) -> bool {
            lib_names.contains(self.0)
        }
    }

    impl HookApplicability for SymbolPresent {
        fn is_applicable(&self, _lib_names: &HashSet<String>) -> bool {
            todo!("SymbolPresent applicability")
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
    unsafe fn apply(&self, hook_service: &mut HookService);
}

fn to_libname(name: &str) -> Option<&str> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"^lib(.*)\.so(\.\d+)*$"#).unwrap();
    }

    let inside = RE.captures(name)?.get(1)?;
    Some(inside.as_str())
}

static HOOKS: &[&dyn Hooks] = &[&openssl::OpenSSLHooks {}];

pub unsafe fn init_hooks(hook_service: &mut HookService) {
    // FIXME: list of disabled hooks

    let modmap = Module::enumerate_modules();
    let libnames = modmap
        .iter()
        .filter_map(|m| to_libname(&m.name).map(|v| v.to_string()))
        .collect::<HashSet<String>>();

    for &hook in HOOKS {
        if hook.applicability().is_applicable(&libnames) {
            unsafe { hook.apply(hook_service) };
        }
    }
}
