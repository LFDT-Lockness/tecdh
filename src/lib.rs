//! This crate implements Threshold Elliptic Curve Diffie-Hellman key
//! exchange.
//!
//! Threshold means that the private key is shared between multiple parties.
//! Only when a threshold amount of parties run the protocol together, can
//! they form the diffie-hellman session key
//!
//! The procedure for running this protocol resembles tBLS signatures, and in
//! fact was directly adpated from <https://eprint.iacr.org/2020/096>. A big
//! difference from BLS is that since we don't need signature verification, we
//! don't need efficient pairings and can use any curve we want.

#![warn(missing_docs, unsafe_code, unused_crate_dependencies)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::unwrap_used, clippy::panic)
)]

/// Functions to perform low-level operations. This can be misused, so they are
/// not recommended unless you know how tECDH works
pub mod lowlevel;
/// Helper types for the MPC execution
pub mod mpc;

/// Start an MPC protocol that performs threshold ECDH with shared private key.
/// Returns the session key
///
/// - `eid` - execution id, a nonce shared by every party
/// - `other_key` - public key of the other party doing the key exchange
/// - `i` - index of party in this protocol invocation, used for message routing
/// - `key_share` - key share to use, can be additive or SSS
/// - `participants` - which key holders are participating in the protocol,
///   given as indexes into `share_preimages` in key share. Ignored for additive
///   shares.
/// - `party` - the `round-based` party
pub async fn start_ecdh<D, E, M>(
    eid: &[u8],
    other_key: generic_ec::NonZero<generic_ec::Point<E>>,
    i: u16,
    key_share: &key_share::CoreKeyShare<E>,
    participants: &[u16],
    party: M,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<generic_ec::Point<E>, mpc::Error>
where
    D: digest::Digest,
    E: generic_ec::Curve,
    M: round_based::Mpc<ProtocolMessage = mpc::Msg<E>>,
{
    let share_preimages = key_share
        .vss_setup
        .as_ref()
        .map({
            |vss_setup| {
                participants
                    .iter()
                    .map(|i| vss_setup.I.get(usize::from(*i)).copied())
                    .collect::<Option<Vec<_>>>()
                    .ok_or(mpc::Error::CreationFailed("share is not SSS"))
            }
        })
        .transpose()?;
    let share_preimages = share_preimages.as_ref().map(|v| v.as_ref());
    let public_shares = &key_share.public_shares;
    let public_shares = participants
        .iter()
        .map(|i| public_shares[usize::from(*i)])
        .collect::<Vec<_>>();

    mpc::run::<D, E, M>(
        eid,
        other_key,
        &key_share.x,
        i,
        key_share.min_signers(),
        &public_shares,
        share_preimages,
        party,
        rng,
    )
    .await
}

/// Error for aggregation failing
#[derive(Debug, Clone, thiserror::Error)]
pub enum AggregateFailed {
    /// Lagrange polynomial construction failed, probably because some points
    /// repeat
    #[error("lagrange interpolation failed")]
    Lagrange,
    /// Party ZKP verification failed
    #[error("honesty verification failed for parties: {0:?}")]
    Verification(Vec<u16>),
}

#[cfg(test)]
mod test {
    type E = generic_ec::curves::Secp256k1;

    #[test_case::test_case(3, 5; "t3n5")]
    #[test_case::test_case(5, 5; "t5n5")]
    #[test_case::test_case(3, 7; "t3n7")]
    fn protocol_same_as_ecdh(t: u16, n: u16) {
        let mut rng = rand_dev::DevRng::new();

        let secret_key = generic_ec::NonZero::<generic_ec::SecretScalar<E>>::random(&mut rng);
        let shares = key_share::trusted_dealer::builder::<E>(n)
            .set_threshold(Some(t))
            .set_shared_secret_key(secret_key.clone())
            .generate_shares(&mut rng)
            .unwrap();

        let data = generic_ec::Point::generator()
            * generic_ec::NonZero::<generic_ec::Scalar<E>>::random(&mut rng);
        let party_indexes = random_participants(n, t, &mut rng);
        let parties = party_indexes
            .iter()
            .map(|x| u16::try_from(*x).unwrap())
            .collect::<Vec<_>>();

        let ecdhs = round_based::sim::run_with_setup(
            party_indexes.iter().copied(),
            |i, party, party_index| {
                let mut rng = rng.fork();
                let share = &shares[party_index];
                let parties = &parties;
                async move {
                    crate::start_ecdh::<sha2::Sha256, _, _>(
                        b"test", data, i, share, parties, party, &mut rng,
                    )
                    .await
                }
            },
        )
        .unwrap()
        .expect_ok()
        .into_vec();

        let golden = crate::lowlevel::ecdh(data, &secret_key);
        for ecdh in &ecdhs {
            assert_eq!(golden, *ecdh);
        }
    }

    fn random_participants<Int: Into<usize>>(
        n: Int,
        t: Int,
        rng: &mut impl rand::RngCore,
    ) -> Vec<usize> {
        let n = n.into();

        let t = t.into();
        assert!(t <= n);
        let mut r = Vec::with_capacity(t);
        for _ in 0..t {
            loop {
                let x = rand::Rng::gen_range(rng, 0..n);
                if !r.contains(&x) {
                    r.push(x);
                    break;
                }
            }
        }
        r
    }
}
