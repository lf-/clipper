// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

fn main() -> std::io::Result<()> {
    tonic_build::compile_protos("proto/embedding.proto")?;
    Ok(())
}
