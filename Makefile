clipper: target/debug/clipper.d

FRIDA_VERSION="16.1.3"

frida-gum:
	curl -L -o frida-gum.tar.xz "https://github.com/frida/frida/releases/download/$(FRIDA_VERSION)/frida-gum-devkit-$(FRIDA_VERSION)-linux-x86_64.tar.xz"
	mkdir frida-gum
	tar -C frida-gum -xf frida-gum.tar.xz

target/build/clipper.d: frida-gum
	export BINDGEN_EXTRA_CLANG_ARGS="-Ifrida-gum"
	export LIBRARY_PATH="frida-gum"
	cargo build --workspace

clean:
	cargo clean
	rm -rf frida-gum
