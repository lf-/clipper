<!--
SPDX-FileCopyrightText: 2023 Jade Lovelace

SPDX-License-Identifier: MPL-2.0
-->

# clipper

This is a project to escrow TLS keys for debugging, named after the notorious
Clipper chip.

## Motivation

It's getting increasingly annoying to debug things since you can't dump clean
request logs given TLS; this requires application support and sucks way more
than doing it in a browser. I would like to be able to essentially get
`fiddler2`/OWASP ZAP results but without requiring applications deal with
proxies or trust weird CAs.

An interesting direction this may go is to attach Chrome devtools via [Chrome
devtools protocol][devtools-net].

[devtools-net]: https://chromedevtools.github.io/devtools-protocol/1-3/Network/

## Design

This is effectively a daemon for receiving [`SSLKEYLOGFILE`] data from some
processes on a system, which can be further used by other systems to provide
transparent interception of traffic (and collation with pcap files).

Maybe the ideal usage of this is to be able to run:

```
clipper app.pcap -- bad-app
```

and the pcap will include all the necessary keys to decrypt all the TLS sent by
the application, regardless of which TLS libraries it uses, without
recompilation.

The layering (WIP) is as follows:
- clipper_inject gets keys and sends them to some desired location. It can be
  used standalone to extract key log files from programs that don't want to
  provide them.
- clipper invokes programs under interception, captures the actual network
  traffic (shells out?), and possibly provides it to other programs to process.

  FIXME: should clipper provide a devtools implementation for interception, or
  should that be a separate tool that communicates with clipper? It could go
  either way; I can see wanting to open pcaps and use them with devtools, which
  is a different use case.

### clipper_inject

This is a `LD_PRELOAD` library which pulls keys out of the following TLS
libraries using Frida GUM:

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

Inspired by [openssl-keylog] and [mirrord-layer] ([blog
post][mirrord-blogpost]).

[`SSLKEYLOGFILE`]: https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
[openssl-keylog]: https://github.com/wpbrown/openssl-keylog
[mirrord-layer]: https://github.com/metalbear-co/mirrord/tree/main/mirrord/layer
[mirrord-blogpost]: https://metalbear.co/blog/mirrord-internals-hooking-libc-functions-in-rust-and-fixing-bugs/

### clipper_dump

`clipper_dump` is a debugging tool for our underlying TLS, TCP, and HTTP
libraries. It allows dumping pcaps and running them through our network
protocol implementations to validate them. It will likely have other
functionality in the future related to this goal.

FIXME: use similar techniques for automated snapshot testing: take a pcap and
turn it into logs.

FIXME: should this actually be a subcommand of `clipper`? How should the CLI
evolve?

Example usage:

```
RUST_LOG=net_decode::tcp_reassemble=info,debug cargo run -p clipper_dump -- dump-pcap corpus/nya-dsb.pcapng
```

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

To test with the current setup:

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

### Chrome Dev Tools

You can crime the included dev tools to connect to another host with:

`devtools://devtools/bundled/inspector.html?ws=localhost:1337`

This is sort of evil but it means that we don't have to build or distribute
devtools, an annoying task.
