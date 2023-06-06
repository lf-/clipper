#![feature(fn_ptr_trait)]
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
use core::fmt;
use std::{
    ffi::{c_char, CStr},
    marker::{FnPtr, PhantomData},
    mem, ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

struct Show<'a>(&'a [u8]);
impl<'a> fmt::Display for Show<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for &ch in self.0 {
            for part in std::ascii::escape_default(ch) {
                fmt::Write::write_char(f, part as char)?;
            }
        }
        write!(f, "\"")
    }
}

/// Safety:
/// FuncType must be a function pointer type, and probably extern "C"!
pub struct LazyDlSym<FuncType: FnPtr> {
    name: &'static [u8],
    value: AtomicPtr<()>,
    _phantom: PhantomData<FuncType>,
}

unsafe fn rt_transmute<T: Copy, U>(x: T) -> U {
    assert_eq!(mem::size_of::<T>(), mem::size_of::<U>());
    let y: U = mem::transmute_copy(&x);
    y
}

impl<FuncType: FnPtr> LazyDlSym<FuncType> {
    // assert_eq does not work in const contexts
    #[allow(clippy::bool_assert_comparison)]
    pub const fn new(name: &'static [u8]) -> LazyDlSym<FuncType> {
        assert!(name[name.len() - 1] == b'\0');

        LazyDlSym {
            name,
            value: AtomicPtr::new(ptr::null_mut()),
            _phantom: PhantomData,
        }
    }

    pub unsafe fn get(&self) -> FuncType {
        let value = self.value.load(Ordering::Relaxed);
        if !value.is_null() {
            let v: FuncType = rt_transmute(value);
            v
        } else {
            let func = libc::dlsym(libc::RTLD_NEXT, self.name.as_ptr() as *const _);
            if func.is_null() {
                panic!("cannot load demanded symbol {}", Show(self.name));
            }
            let v: FuncType = rt_transmute(func);
            v
        }
    }
}

mod ssl {
    // FIXME: probably should use bindgen to generate these crimes, but also,
    // this is some high tier crime code
    use std::ffi::c_char;

    use crate::LazyDlSym;

    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct SSL(*mut ());

    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct SSL_CTX(*mut ());

    pub type SSL_CTX_keylog_cb_func = extern "C" fn(SSL, *const c_char);

    pub static SSL_new: LazyDlSym<extern "C" fn(SSL_CTX) -> SSL> = LazyDlSym::new(b"SSL_new\0");
    pub static SSL_CTX_set_keylog_callback: LazyDlSym<
        extern "C" fn(SSL_CTX, SSL_CTX_keylog_cb_func),
    > = LazyDlSym::new(b"SSL_CTX_set_keylog_callback\0");
}

extern "C" fn keylog_callback(_ssl: ssl::SSL, s: *const c_char) {
    let s = unsafe { CStr::from_ptr(s) };
    eprintln!("nya!! {s:?}");
}

#[no_mangle]
unsafe extern "C" fn SSL_new(ctx: ssl::SSL_CTX) -> ssl::SSL {
    eprintln!("teehee");
    ssl::SSL_CTX_set_keylog_callback.get()(ctx, keylog_callback);
    ssl::SSL_new.get()(ctx)
}
