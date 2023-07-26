<!--
SPDX-FileCopyrightText: 2023 Jade Lovelace

SPDX-License-Identifier: MPL-2.0
-->

# clipper

The Clipper project allows you to easily debug HTTPS traffic of unmodified
native applications, completely unprivileged (on Linux), without introducing
any application-level tampering. It allows you to attach Chrome Dev Tools to
most applications and view all their traffic as well as dump PCAPng files
with included decryption keys, in one command.

## Acquiring it

The easiest way to get a build of Clipper is to use Nix:

`nix --extra-experimental-features 'nix-command flakes' build github:lf-/clipper`

Then you will have a `clipper` in `result/bin`.

Otherwise, see [Development](#development).

## Usage: pcaps

```
$ clipper capture -o nya.pcapng bash
[jade@tail-bot clipper]$ curl https://google.com
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="https://www.google.com/">here</A>.
</BODY></HTML>
[jade@tail-bot clipper]$ exit

# You can look at the decrypted packets in tshark/wireshark:

$ tshark -r nya.pcapng -T fields -e '_ws.col.Info'
<...>
HEADERS[1]: GET /
443 → 43278 [ACK] Seq=6789 Ack=742 Win=65535 Len=0
SETTINGS[0], WINDOW_UPDATE[0]
SETTINGS[0]
SETTINGS[0]
DATA[1]
43278 → 443 [ACK] Seq=773 Ack=8139 Win=63000 Len=0
DATA[1] (text/html)
PING[0]

# You can look at recorded pcaps in DevTools

$ cargo run -p clipper -- devtools-server ./nya.pcapng
 INFO clipper::devtools: Listening on ws://127.0.0.1:6830
 INFO clipper::devtools: Browse to this URL in Chromium to view: devtools://devtools/bundled/inspector.html?ws=localhost:6830
```

![screenshot of chrome devtools showing one request to google.com performed by
curl](./docs/assets/chrome-devtools-demo.png)

## Usage: live DevTools

```
$ cargo build --workspace && cargo run -p clipper -- capture-devtools bash
 INFO clipper::devtools: Listening on ws://127.0.0.1:6830
 INFO clipper::devtools: Browse to this URL in Chromium to view: devtools://devtools
/bundled/inspector.html?ws=localhost:6830
[jade@tail-bot clipper]$ curl https://jade.fyi/robots.txt
User-agent: *
Disallow:
Allow: /
Sitemap: https://jade.fyi/sitemap.xml
[jade@tail-bot clipper]$ curl -X POST -d 'nya nya nya' https://jade.fyi/robots.txt
<html>
<head><title>405 Not Allowed</title></head>
<body>
<center><h1>405 Not Allowed</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

https://github.com/lf-/clipper/assets/6652840/e4557bd1-e6a6-4491-bfb8-c04bf8198085

## Usage: SSLKEYLOGFILE

Most programs use TLS libraries that support generating data of
[`SSLKEYLOGFILE`][SSLKEYLOGFILE] format, but do not implement the environment
variable to activate it. `clipper_inject` can activate this functionality at
runtime for programs using supported TLS libraries, without using any of the
other functionality of the Clipper suite.

To do this, invoke a program with `LD_PRELOAD=/path/to/clipper_inject.so
SSLKEYLOGFILE=somefile.log yourprogram`. For example:

```
$ cargo build --workspace
$ LD_PRELOAD=target/debug/libclipper_inject.so SSLKEYLOGFILE=keys.log curl https://google.com/robots.txt
$ head -n2 keys.log
SERVER_HANDSHAKE_TRAFFIC_SECRET 4dfb176a8e60669decb212502a1c69b4b4df0709af38f2f2b564e0fc9ee4f2c2 f51cdc5ffb6fc96ce7f334fdbcc2d3f681795d11846bc11bdef566148eb2980b7dc6654f0c13133a5fd1153d9188a4f1
EXPORTER_SECRET 4dfb176a8e60669decb212502a1c69b4b4df0709af38f2f2b564e0fc9ee4f2c2 d47eaf1623dacd6dad4c4059a7e11c269e4c99ec9eba8911c0c2bd70f56224806fc2e95d6edc5b439fa5a7d51efb4735
```

## Internal IP addresses

The container is in the IP space 10.0.2.0/24, with a gateway at 10.0.2.2, DNS
at 10.0.2.3. You can access host localhost services on 10.0.2.2.

## Name

Clipper is named after the [Clipper chip], a US government attempt to require
all encryption to be breakable in the early '90s (what's old is new again),
because just like the Clipper chip, it steals your keys. However, unlike the
Clipper chip, Clipper gives its users agency.

[Clipper chip]: https://en.wikipedia.org/wiki/Clipper_chip

## Design

### `clipper`

The Clipper host process contains the following:
* a daemon for receiving [`SSLKEYLOGFILE`] data from some processes on a system
  by gRPC over a Unix socket (FIXME: allow key gathering from remote systems
  e.g. Android)
* a packet capture system
* network decoding stack (`net_decode`)
* a Chrome Dev Tools Protocol implementation (`devtools_server`,
  `clipper::devtools`)
* rootless Linux container execution (`wire_blahaj::unprivileged`)

Inside the container, processes are run with `clipper_inject` injected with
`LD_PRELOAD`, which intercepts all the TLS keys and sends them onwards.

You can get debug logging for `clipper` using the `RUST_LOG` environment
variable, with [tracing-subscriber semantics][tracing-debug-log].

### `clipper_inject`

This is a `LD_PRELOAD` library which can currently pull keys out of the
following TLS libraries using Frida GUM:

- [x] OpenSSL
- [x] rustls
- [ ] go [crypto/tls](https://pkg.go.dev/crypto/tls)
- [ ] NSS
- [ ] GnuTLS
- [ ] boringssl

It can then send the keys onwards. Planned ways to send them onwards:

- [x] Print to stdout
- [x] Implement SSLKEYLOGFILE
- [x] Send to clipper service over an IPC socket

The debug logging for `clipper_inject` can be controlled with `CLIPPER_LOG`
with [tracing-subscriber semantics][tracing-debug-log].

[tracing-debug-log]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html

Inspired by [openssl-keylog] and [mirrord-layer] ([blog
post][mirrord-blogpost]).

[SSLKEYLOGFILE]: https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
[openssl-keylog]: https://github.com/wpbrown/openssl-keylog
[mirrord-layer]: https://github.com/metalbear-co/mirrord/tree/main/mirrord/layer
[mirrord-blogpost]: https://metalbear.co/blog/mirrord-internals-hooking-libc-functions-in-rust-and-fixing-bugs/

### Implementation notes: packet capture

In order to capture packets, we need to have CAP_NET_ADMIN and CAP_NET_RAW.
This is not possible without being (effectively) root. Fortunately, being root
is simply a matter of fiddling around with namespaces until you are.

Specifically, we need a network namespace and root access inside the container.
Getting communication *out* of the container is more challenging since you
cannot link interfaces between namespaces without root. However, you *can* run
a [userspace TCP stack with slirp4netns][userspace-tcp], and we can probably
crib some stuff from [rootlesskit].

All of this together should let us either use or become tcpdump and affect
only our own child processes (which would be a success!).

[userspace-tcp]: https://github.com/rootless-containers/slirp4netns
[rootlesskit]: https://github.com/rootless-containers/rootlesskit

To capture with tcpdump and attach Clipper'd key logs:

```
(in one terminal)
$ sudo tcpdump -w nya.pcap 'tcp port 443'; editcap --inject-secrets 'tls,nya.ssl_log' nya.pcap nya-dsb.pcapng
(in another terminal, after starting the first. hit ctrl c on the first when done)
$ cargo b --workspace && LD_PRELOAD=./target/debug/libclipper_inject.so SSLKEYLOGFILE=nya.ssl_log target/debug/rustls-fixture
```

### Note on why to use Frida

Unfortunately, libraries consider it impolite behaviour to go override their
internal calls of functions, and some of them even use measures such
as `-Bsymbolic` ([see this article][bsymbolic]) that result in internal calls
not dispatching through the GOT/PLT dynamic linking machinery and thus not
being possible to override.

For example: calls to `SSL_new` from within libssl will directly dispatch to
the function inside libssl, disregarding what is going on with LD_PRELOAD.

The result of this is that if we want to intercept all calls period, we need to
use more powerful hooking primitives, such as those provided by Frida, which
will replace the actual functions by our hooks by modifying the program code.

[bsymbolic]: https://www.technovelty.org/c/what-exactly-does-bsymblic-do.html

### TLS interception implementation

It looks like tls-parser does not actually support decrypting sessions. So
that's No Fun. However, I am also not foolish enough to write a TLS
implementation. Thus we are forking rustls to do horrible horrible crimes to
it and poke all the internals. Exciting!

## Known issues

- Capture is not supported on non-Linux systems. Probably the way to implement
  this is to expect to be run as root, then drop privs to `SUDO_UID` and
  `SUDO_GID` after starting capture. We would likely want to use libpcap or
  suchlike to do multi-platform properly.

  It's also unclear how to restrict to *just* the processes we care about
  capturing.

  However, I only have Linux computers, so this is a low priority issue I
  also physically can't fix.
- `clipper_inject` could probably use to be ported to macOS. This should not
  actually be that hard, but it is annoying. For example, use
  `DYLD_INSERT_LIBRARIES` instead of `LD_PRELOAD`, and fix up references to
  `.so` files.
- Chrome says "Provisional headers" on our requests. I don't know why this is
  exactly, and I would somewhat like to fix it but it is merely visual.
- We rely on the built-in dev tools in Chromium. This is OK but it would be
  nicer to be able to use it in Firefox too. Note that there is a [bug in the
  chrome-devtools-frontend NPM package that means we would have to build it
  ourselves](https://crbug.com/1465671), which I am not going to do.

  Another benefit of shipping our own dev tools is that we could remove the
  unhelpful tabs and stop trying to screencast the page automatically.
- We don't support TLS 1.2. It could be useful, in some circumstances, but I am
  probably not going to write the code soon.
- We don't support HTTP/3. Maybe one day, but this requires both DTLS and
  HTTP/3 parsing.
- There's definitely some prototype quality code in the project, and we could
  use to test against more samples of TLS and HTTP.

## Development

### Build setup

Clipper requires a nightly Rust compiler to build. I used 1.73.0-nightly
(2023-07-09) but anything recent should work.

Since frida-gum is written in C it makes Clipper slightly annoying to build. I
want to make this less annoying in the future, but I just haven't figured out
how I plan to do so yet without losing Nix compatibility. You'll need to have a
built frida-gum, for example by downloading one:

```
$ curl -L -o frida-gum.tar.xz "https://github.com/frida/frida/releases/download/16.1.3/frida-gum-devkit-16.1.3-linux-x86_64.tar.xz"
$ mkdir frida-gum
$ tar -C frida-gum -xf frida-gum.tar.xz

# Make bindgen see it:

$ export BINDGEN_EXTRA_CLANG_ARGS="-I$(pwd)/frida-gum"
$ export LIBRARY_PATH="$(pwd)/frida-gum"
```

Alternatively, use `nix develop` and then it will pick it up for you
automatically (although it will then possibly link to Nix stuff which may be
inconvenient if you're not on NixOS due to `clipper_inject` being a
`LD_PRELOAD` library; though this seems to be totally fine on my Arch box,
surprisingly).

Remember to run `cargo build --workspace` such that you have a
`libclipper_inject.so` built before running `clipper`.

## Contributing

Contributions are accepted but please check with me by filing an issue
prior to making new features or major changes. Clipper is a one-person
volunteer project, and requests may be rejected for reasons of time or
maintenance burden.
