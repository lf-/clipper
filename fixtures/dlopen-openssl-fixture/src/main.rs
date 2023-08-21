// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use std::ffi::{c_char, CStr, CString};

type OpensslFixtureMain = fn() -> Result<(), libfixture::Error>;

const FILE: &'static str = env!("CARGO_CDYLIB_FILE_OPENSSL_FIXTURE_openssl-fixture");

fn main() -> Result<(), libfixture::Error> {
    let file = CString::new(FILE).unwrap();
    let h = unsafe { libc::dlopen(file.as_ptr(), libc::RTLD_LOCAL | libc::RTLD_LAZY) };
    if h.is_null() {
        panic!("failed to dlopen: {:?}", unsafe {
            CStr::from_ptr(libc::dlerror())
        })
    }

    let sym = unsafe { libc::dlsym(h, b"openssl_fixture_main\0".as_ptr() as *const c_char) };

    // if it's null this is never right *for us*
    if sym.is_null() {
        panic!("failed to dlsym: {:?}", unsafe {
            CStr::from_ptr(libc::dlerror())
        });
    }

    let fun: OpensslFixtureMain = unsafe { std::mem::transmute(sym) };

    fun()
}
