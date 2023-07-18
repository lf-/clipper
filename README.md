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

## Usage: pcaps

```
$ cargo run -p clipper -- capture -o nya.pcapng bash
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
$ cargo run -p clipper -- capture-devtools bash
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

https://github.com/lf-/clipper/assets/6652840/47a07fdf-e73b-4a12-b15a-df4812a34c24

## Name

Clipper is named after the [Clipper chip], a US government attempt to require
all encryption to be breakable (what's old is new again), because just like the
Clipper chip, it steals your keys. However, unlike the Clipper chip, Clipper
gives its users agency.

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

[`SSLKEYLOGFILE`]: https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
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
