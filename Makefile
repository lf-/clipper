clipper: target/debug/clipper.d

frida-gum:
	curl -L -o frida-gum.tar.xz "https://github.com/frida/frida/releases/download/16.1.3/frida-gum-devkit-16.1.3-linux-x86_64.tar.xz"
	mkdir frida-gum
	tar -C frida-gum -xf frida-gum.tar.xz

target/build/clipper.d: frida-gum
	export BINDGEN_EXTRA_CLANG_ARGS="-Ifrida-gum"
	export LIBRARY_PATH="frida-gum"
	cargo build --workspace

