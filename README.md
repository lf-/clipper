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
- [ ] Implement SSLKEYLOGFILE
- [ ] Send to clipper service over an IPC socket

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

