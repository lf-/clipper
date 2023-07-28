# SPDX-FileCopyrightText: 2023 Elliana May
#
# SPDX-License-Identifier: MPL-2.0

clipper: target/debug/clipper.d

FRIDA_VERSION="16.1.3"

frida-gum:
	curl -L -o frida-gum.tar.xz "https://github.com/frida/frida/releases/download/$(FRIDA_VERSION)/frida-gum-devkit-$(FRIDA_VERSION)-linux-x86_64.tar.xz"
	mkdir frida-gum
	tar -C frida-gum -xf frida-gum.tar.xz


target/debug/clipper.d: frida-gum
	BINDGEN_EXTRA_CLANG_ARGS="-I$$(pwd)/frida-gum" LIBRARY_PATH="$$(pwd)/frida-gum" cargo build --workspace

clean:
	cargo clean
	rm -rf frida-gum
