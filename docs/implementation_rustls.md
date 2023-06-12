# Implementation notes for rustls

We definitely have to fork because everything is `pub(crate)`, which is a good
choice if you want a secure TLS library that people don't screw up, but we are
here to screw it up.

`RecordLayer` seems to be the main structure for bringing up
encryption/decryption and is otherwise quite central.

## keys added and removed here

Grepping for `key_log.log` is probably a great idea for finding where the key
material needs to be put in. Also `derive_logged_secret`.

## tls 1.3

`KeySchedule::set_encrypter` brings up the encrypter.

## tls 1.2

`CommonState::start_encryption_tls12` calls
`RecordLayer::prepare_message_encrypter` and decrypter. It is itself called by
`CompleteServerHelloHandling::handle_server_hello` as well as
`ExpectServerDone::handle`.

## Where we need to split

I think that the right spot to split the library is at `ConnectionCore<Data>`,
because it is where communication starts to be done (and particularly,
communication which is inconvenient since it involves trying to send things to
both sides).
