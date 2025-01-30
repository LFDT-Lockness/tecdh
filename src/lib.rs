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

/// Helper types for the MPC execution
pub mod mpc;
use generic_ec_zkp::dlog_eq::non_interactive as dlog_eq;

/// Compute elliptic curve diffie-hellman for the given public key received from
/// another party and a private key for this party
pub fn ecdh<E: generic_ec::Curve>(
    pubkey1: generic_ec::NonZero<generic_ec::Point<E>>,
    privkey2: &generic_ec::NonZero<generic_ec::SecretScalar<E>>,
) -> generic_ec::NonZero<generic_ec::Point<E>> {
    pubkey1 * privkey2
}

/// Evaluation of partial ECDH as outputted by parties, computed by
/// [`partial_ecdh`]. `t` partials can be aggregated with [`aggregate`]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct PartialEvaluation<E: generic_ec::Curve> {
    /// Index of evaluating party
    pub i: u16,
    /// Partial session key
    pub v: generic_ec::NonZero<generic_ec::Point<E>>,
    /// ZK proof
    pub pi: dlog_eq::Proof<E>,
}

/// Compute partial result of key exchange, with `secret_share` being a share of
/// this party's private key. Use [`aggregate`] to aggregate multiple such
/// partial evaluations into a full session key.
///
/// Together with partial session key, a proof of honest correctness is
/// computed. Every party is required to send this proof together with their
/// partial evaluation for aggregation.
///
/// In paper this function is called `PartialEval(x, sk_i, vk_i)`, section IV.A
///
/// - `eid` - execution id, used to prevent replay attacks. All parties
///   computing the partial evaluations should agree on this value. This value
///   cannot be reused between executions as that leads to replay attacks
/// - `i` - index of this party among other computing parties. If `t` parties
///   are performing the partial evaluation, each index should be from `0` to `t
///   - 1`. When using [`aggregate`], partial evaluations should be sorted by
///   this index.
/// - `other_key` - `H_1(x)` in paper, public key of the other party doing the
///    key exchange
/// - `secret_share` - `sk` from paper, share of the private key of the party
///    doing this key exchange. The `vk` argument which is present in paper but
///    not here is computed from it
pub fn partial_ecdh<E: generic_ec::Curve, D: digest::Digest>(
    eid: &[u8],
    i: u16,
    other_key: generic_ec::NonZero<generic_ec::Point<E>>,
    secret_share: &generic_ec::NonZero<generic_ec::SecretScalar<E>>,
    rng: &mut impl rand_core::CryptoRngCore,
) -> PartialEvaluation<E> {
    let value = other_key * secret_share;
    let proof_data = dlog_eq::Data::from_secret_key(secret_share, other_key.into_inner());
    let shared_state = SharedState {
        eid,
        prover_index: i,
    };
    let proof = dlog_eq::prove::<E, D>(rng, &shared_state, secret_share, proof_data);
    PartialEvaluation {
        i,
        v: value,
        pi: proof,
    }
}

/// Aggregate partial ECDH session keys into a full session key
///
/// - `share_preimages` - should be `None` for additive key shares. For SSS, it
///   gives the points at which the keyshare values are computed, and should be in
///   the same order by participant as `partials`.
/// - `other_key` - `H_1(x)` in paper, public key of the other party doing the
///    key exchange
/// - `public_shares` - list of public shares of parties who computed partial
///   evaluations, given in the same order as partials and share preimages. `VK` in
///   paper
/// - `partials` - `E` in paper, partial ECDH session keys
///
/// In paper this function is called `Combine(pk, VK, x, E)`, section IV.A
pub fn aggregate<E: generic_ec::Curve, D: digest::Digest>(
    eid: &[u8],
    other_key: generic_ec::NonZero<generic_ec::Point<E>>,
    partials: &[PartialEvaluation<E>],
    public_shares: &[generic_ec::NonZero<generic_ec::Point<E>>],
    share_preimages: Option<&[generic_ec::NonZero<generic_ec::Scalar<E>>]>,
) -> Result<generic_ec::Point<E>, AggregateFailed> {
    // Verify the proofs
    let mut blame = Vec::new();
    for (partial, pub_share) in partials.iter().zip(public_shares) {
        let shared_state = SharedState {
            eid,
            prover_index: partial.i,
        };
        let data = dlog_eq::Data {
            gen1: generic_ec::Point::generator().into(),
            prod1: pub_share.into_inner(),
            gen2: other_key.into_inner(),
            prod2: partial.v.into_inner(),
        };
        if dlog_eq::verify::<E, D>(&shared_state, data, partial.pi).is_err() {
            blame.push(partial.i);
        };
    }
    // The paper suggests to continue with an honest subset, but we prefer to
    // abort
    if !blame.is_empty() {
        return Err(AggregateFailed::Verification(blame));
    }

    // Compute the aggregate session key
    if let Some(share_preimages) = share_preimages {
        // shamir aggregation
        let lagrange_coefficients = (0..(share_preimages.len()))
            .map(|j| generic_ec_zkp::polynomial::lagrange_coefficient_at_zero(j, share_preimages))
            .collect::<Option<Vec<_>>>()
            .ok_or(AggregateFailed::Lagrange)?;
        Ok(generic_ec::Scalar::multiscalar_mul(
            lagrange_coefficients
                .into_iter()
                .zip(partials.iter().map(|t| t.v)),
        ))
    } else {
        // additive aggregation
        Ok(partials.iter().map(|t| t.v).sum())
    }
}

/// Shared state between proving in [`partial_ecdh`] and verifying in
/// [`aggregate`]
#[derive(udigest::Digestable)]
struct SharedState<'a> {
    eid: &'a [u8],
    prover_index: u16,
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


#[cfg(test)]
mod test {
    type E = generic_ec::curves::Secp256k1;

    #[test_case::test_case(3, 5; "t3n5")]
    #[test_case::test_case(5, 5; "t5n5")]
    #[test_case::test_case(3, 7; "t3n7")]
    fn aggregate_same_as_ecdh(t: u16, n: u16) {
        let t_ = if t == n { None } else { Some(t) };
        let t = usize::from(t);
        let mut rng = rand_dev::DevRng::new();

        let secret_key = generic_ec::NonZero::<generic_ec::SecretScalar<E>>::random(&mut rng);
        let shares = key_share::trusted_dealer::builder::<E>(n)
            .set_threshold(t_)
            .set_shared_secret_key(secret_key.clone())
            .generate_shares(&mut rng)
            .unwrap();
        let public_shares = &shares[0].public_shares;
        let share_preimages = shares[0].vss_setup.as_ref().map(|vss| &vss.I[0..t]);

        let data = generic_ec::Point::generator()
            * generic_ec::NonZero::<generic_ec::Scalar<E>>::random(&mut rng);
        let eid = b"test";

        let ecdh = super::ecdh(data, &secret_key);
        let partials = shares
            .iter()
            .zip(0..)
            .map(|(s, i)| super::partial_ecdh::<E, sha2::Sha256>(eid, i, data, &s.x, &mut rng))
            .collect::<Vec<_>>();
        let restored = super::aggregate::<E, sha2::Sha256>(
            eid,
            data,
            &partials[0..t],
            public_shares,
            share_preimages,
        )
        .unwrap();

        assert_eq!(restored, ecdh);
    }

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

        let golden = super::ecdh(data, &secret_key);
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
