# tECDH - threshold elliptic-curve Diffie-Hellman key exchange

This crate implements tECDH - when one of the Diffie-Hellman keys is kept as
key shares. Multiple parties, when activated with a common
`counterparty_public_key`, will execute the protocol to obtain a DH session
key.

The procedure for running this protocol resembles tBLS signatures, and in
fact was directly adpated from <https://eprint.iacr.org/2020/096>. A big
difference from BLS is that since we don't need signature verification, we
don't need efficient pairings and can use any curve we want.

## How to use the library

In short, you will need to load the key shares, establish network connection
between parties, obtain a shared execution id, match the party indicies, and
then commence the protocol.

```rust,no_run
# async fn _example() {
use tecdh::{round_based, generic_ec};
# use std::{pin::Pin, task::{Context, Poll}};
# struct Example<T>(std::marker::PhantomData<T>);
# impl<T> round_based::Stream for Example<T> {
#     type Item = T;
#     fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> { todo!() }
# }
# impl<T> round_based::Sink<T> for Example<T> {
#     type Error = std::io::Error;
#     fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { todo!() }
#     fn start_send(self: Pin<&mut Self>, _: T) -> Result<(), Self::Error> { todo!() }
#     fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { todo!() }
#     fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { todo!() }
# }
// Curve of your choice
type E = generic_ec::curves::Ed25519;
// The unique execution ID which the parties agree to before starting
let execution_id: Vec<u8> = todo!();
// The key of the counterparty you're performing the ECDH handshake with
let counterparty: generic_ec::NonZero<generic_ec::Point<E>> = todo!();
// The key share that was generated in advance and is now loaded from
// persistent storage
let key_share: tecdh::key_share::CoreKeyShare<E> = todo!();
// The network setup using `round-based`
fn make_incoming() -> impl round_based::Stream<Item = Result<round_based::Incoming<tecdh::mpc::Msg<E>>, std::io::Error>>
#     { Example(std::marker::PhantomData) }
fn make_outgoing() -> impl round_based::Sink<round_based::Outgoing<tecdh::mpc::Msg<E>>, Error = std::io::Error>
#     { Example(std::marker::PhantomData) }
let party = round_based::MpcParty::connected((make_incoming(), make_outgoing()));
// Match party indicies from keygen to the current participants (not used for
// additive key shares)
let participant_indicies: &[u16] = todo!();
let this_party_index: u16 = todo!();

// Run the protocol
let session_key = tecdh::start::<sha2::Sha256, E, _>(
    &execution_id,
    counterparty,
    this_party_index,
    &key_share,
    participant_indicies,
    party,
    &mut rand::rngs::OsRng,
).await.unwrap();
# }
```

### Distributed key generation

First of all, you will need to generate a key that the distributed parties will
use. For that purpose, you can use any secure DKG protocol. We recommend using
[cggmp21-keygen](https://docs.rs/cggmp21-keygen/0.5.0/cggmp21_keygen/) --- it's
an interactive protocol built on the same foundations of `round-based` and
`generic-ec`.

### Networking

This library relies on [`round-based`](https://crates.io/crates/round-based)
for the MPC backend, which means the networking interface should be constructed
using its primitives, which are in practice the `Sink` and `Stream` types from
`futures_core`.

The exact underlying mechanism behind the sink and stream depend on the
application and are not provided here. Some application will use libp2p, others
may want to use a message broker like kafka or postgres.  
No matter the implementation, all messages need to be authenticated --- when
one party receives a message from another, it needs to be able to verify that
the message comes from the claimed sender.

### Signer indicies

We use indices to uniquely refer to particular signers sharing a key. Each
index `i` is an unsigned integer `u16` with `0 ≤ i < n` where `n` is the total
number of participants in the protocol.

All signers should have the same view about each others’ indices. For instance,
if Signer A holds index 2, then all other signers must agree that `i=2`
corresponds to Signer A. These indicies must match between the
keygen an the protocol execution.

Assuming some sort of PKI (which would anyway likely be used to ensure secure
communication, as described above), each signer has a public key that uniquely
identifies that signer. It is then possible to assign unique indices to the
signers by lexicographically sorting the signers’ public keys, and letting the
index of a signer be the position of that signer’s public key in the sorted
list.

### Execution ID

Execution of our protocols requires all participants to agree on unique
execution ID (aka session identifier) that is assumed never to repeat. This
string provides context separation between different executions of the protocol
to ensure that an adversary attack the protocol by replaying messages from one
execution to another.

## Join us in Discord!
Feel free to reach out to us [in Discord](https://discordapp.com/channels/905194001349627914/1285268686147424388)!
