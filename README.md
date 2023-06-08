# clipper

This is a project to escrow TLS keys for debugging, named after the notorious
Clipper chip.

## Motivation

It's getting increasingly annoying to debug things since you can't dump clean
request logs given TLS; this requires application support and sucks way more
than doing it in a browser. I would like to be able to essentially get
`fiddler2`/OWASP ZAP results but without requiring applications deal with
proxies or trust weird CAs.

## Design

This is effectively a daemon for receiving [`SSLKEYLOGFILE`] data from various
processes on a system, which can be further used by other systems to provide
transparent interception of traffic (and collation with pcap files).

Maybe the ideal usage of this is to be able to run:

```
clipper app.pcap -- bad-app
```

and the pcap will include all the necessary keys to decrypt all the TLS sent by
the application, regardless of which TLS libraries it uses, without
recompilation.

This client would do all the crimes necessary to achieve this, most likely
including LD_PRELOAD injecting GnuTLS, OpenSSL and variants, and NSS. In order
to get rustls, I think we would probably have to become an in-process debugger
or otherwise do actual code injection, which is pretty horrible, since it's
statically linked.

The tentative design of this program is to provide a server side D-Bus
interface to send the keys to.

> **Note**:
>
> I am not sure if this is actually a great design, since this seems a little bit
> excessive for something that doesn't have to be done super frequently and isn't
> that much data. That said, one benefit of it is that it would make the process
> of capturing somewhat smoother? I dunno.
>
> It would be cool to be able to intercept running processes without having to
> restart them, and be able to enable this at runtime. Is this Too Much? idk.
>
> For now maybe let's implement the universal logging stuff and then attack the
> issue of the daemon later.

Inspired by [openssl-keylog] and [mirrord-layer] ([blog
post][mirrord-blogpost]).

[`SSLKEYLOGFILE`]: https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
[openssl-keylog]: https://github.com/wpbrown/openssl-keylog
[mirrord-layer]: https://github.com/metalbear-co/mirrord/tree/main/mirrord/layer
[mirrord-blogpost]: https://metalbear.co/blog/mirrord-internals-hooking-libc-functions-in-rust-and-fixing-bugs/

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

