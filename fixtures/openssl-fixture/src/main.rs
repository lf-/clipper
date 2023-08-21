// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

use libfixture::Error;
mod contents;

fn main() -> Result<(), Error> {
    crate::contents::openssl_fixture_main()
}
