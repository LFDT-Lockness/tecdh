//! This crate implements digesting into elliptic curve points keyed with a
//! secret scalar for this curve. This digest resembles BLS signatures, but
//! because we don't do signature verification, we're not limited in the choice
//! of curves. Hashing to curve is based on rfc9380 with SHA2 hash and
//! expand_message_xmd expansion. The procedure for a digest is as follows:
//!
//! 1. Input parameters:
//!     * `E` - an elliptic curve
//!     * `m` - message to digest, given as a byte string
//!     * `x` - secret key, given as a scalar for `E`
//! 2. Initialize `i` to 0
//! 2. Use the procedure in rfc9380 to hash the data `i as u8 || m` to curve point `p`
//! 4. If `p` the procedure failed, or if `p` is zero or an invalid point,
//!    increment `i` and retry from step *3*. If 256 attempts have already
//!    elapsed, abort
//! 5. Compute `p * x`
//!
//! The distributed digest is based on https://eprint.iacr.org/2020/096
//! That is, the partial digest is computed in the same way as a regular digest
//! albeit with a shared key, and in addition a ZK proof of honest digest
//! computation is produced, which is checked when aggregating partial digests.
//! We use the DDH-based DVRF instatiation with non-compact proofs

#![warn(missing_docs, unsafe_code, unused_crate_dependencies)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::unwrap_used, clippy::panic)
)]

/// Helper types for the MPC execution
pub mod mpc;
mod zkp;

/// Compute digest of `data` keyed with `secret_key`
pub fn digest<D: digest::Digest, E: internal::HashToCurve>(
    data: &[u8],
    secret_key: &generic_ec::NonZero<generic_ec::SecretScalar<E>>,
) -> generic_ec::NonZero<generic_ec::Point<E>> {
    let plain = hash_to_curve(data, b"dfns-bls-style-hash");
    plain * secret_key
}

/// Evaluation of partial digest as outputted by parties, computed by
/// [`partial_digest`]. `t` partials can be aggregated with [`aggregate`]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct PartialEvaluation<E: generic_ec::Curve> {
    /// Index of evaluating party
    pub i: u16,
    /// Partial digest
    pub v: generic_ec::NonZero<generic_ec::Point<E>>,
    /// ZK proof
    pub pi: zkp::Proof<E>,
}

/// Compute partial digest of `data` keyed with a key of which `secret_share` is a
/// share of. Use [`aggregate`] to aggregate multiple partial digests into a full
/// digest
///
/// Together with digest a proof of honest correctness is computed. Every party
/// is required to send this proof together with partial digest for aggregation.
///
/// In paper this function is called `PartialEval(x, sk_i, vk_i)`, section IV.A
///
/// - `eid` - execution id, used to prevent replay attacks. All parties
///   computing partial digests should agree on this value. This value cannot be
///   reused between executions as that leads to replay attacks
/// - `i` - index of this party among other computing parties. If `t` parties
///   are computing partial digests, each index should be from `0` to `t - 1`.
///   When using [`aggregate`], partial digests and proofs should be sorted by
///   this index.
/// - `data` - `x` in paper
/// - `secret_share` - `sk` from paper. The `vk` argument in paper is computed
///   from it
pub fn partial_digest<D: digest::Digest, E: internal::HashToCurve>(
    eid: &[u8],
    i: u16,
    data: &[u8],
    secret_share: &generic_ec::NonZero<generic_ec::SecretScalar<E>>,
    rng: &mut impl rand_core::RngCore,
) -> PartialEvaluation<E> {
    let plain = hash_to_curve(data, b"dfns-bls-style-hash");
    let digest = plain * secret_share;
    let proof_data = zkp::Data {
        pub_share: (generic_ec::Point::generator() * secret_share).into_inner(),
        base: plain.into_inner(),
        value: digest.into_inner(),
    };
    let r = generic_ec::Scalar::random(rng);
    let shared_state = zkp::SharedState {
        eid,
        prover_index: i,
    };
    let proof = zkp::prove::<D, E>(&shared_state, secret_share, proof_data, r);
    PartialEvaluation {
        i,
        v: digest,
        pi: proof,
    }
}

/// Aggregate `partials` - partial digest values - into a full value.
///
/// - `share_preimages` - should be `None` for additive key shares. For SSS, it
///   gives the points at which the keyshare values are computed, and should be in
///   the same order by participant as `partials`.
/// - `data` - `x` in paper
/// - `public_shares` - list of public shares of parties who computed partial
///   digests, given in the same order as partials and share preimages. `VK` in
///   paper
/// - `partials` - `E` in paper
///
/// In paper this function is called `Combine(pk, VK, x, E)`, section IV.A
pub fn aggregate<D: digest::Digest, E: internal::HashToCurve>(
    eid: &[u8],
    data: &[u8],
    partials: &[PartialEvaluation<E>],
    public_shares: &[generic_ec::NonZero<generic_ec::Point<E>>],
    share_preimages: Option<&[generic_ec::NonZero<generic_ec::Scalar<E>>]>,
) -> Result<generic_ec::Point<E>, AggregateFailed> {
    let base = hash_to_curve(data, b"dfns-bls-style-hash");

    // Verify the proofs
    let mut blame = Vec::new();
    for (partial, pub_share) in partials.iter().zip(public_shares) {
        let shared_state = zkp::SharedState {
            eid,
            prover_index: partial.i,
        };
        let data = zkp::Data {
            pub_share: pub_share.into_inner(),
            base: base.into_inner(),
            value: partial.v.into_inner(),
        };
        if zkp::verify::<D, E>(&shared_state, data, partial.pi).is_err() {
            blame.push(partial.i);
        };
    }
    // The paper suggests to continue with an honest subset, but we prefer to
    // abort
    if !blame.is_empty() {
        return Err(AggregateFailed::Verification(blame));
    }

    // Compute the aggregate digest
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

/// Start an MPC protocol that digests the data with shared private key. Returns
/// digested data
///
/// - `eid` - execution id, a nonce shared by every party
/// - `data` - byte string to digest
/// - `i` - index of party in this protocol invocation, used for message routing
/// - `key_share` - key share to use, can be additive or SSS
/// - `participants` - which key holders are participating in the protocol,
///   given as indexes into `share_preimages` in key share. Ignored for additive
///   shares.
/// - `party` - the `round-based` party
pub async fn start_digest<D, E, M>(
    eid: &[u8],
    data: &[u8],
    i: u16,
    key_share: &key_share::CoreKeyShare<E>,
    participants: &[u16],
    party: M,
    rng: &mut impl rand_core::RngCore,
) -> Result<generic_ec::Point<E>, mpc::Error>
where
    D: digest::Digest,
    E: internal::HashToCurve,
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
        data,
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

mod internal {
    pub trait HashToCurve: generic_ec::Curve {
        /// This function may fail, but the probability of that must be low. If
        /// it fails, we retry with a different prefix. If it fails too many
        /// times, we panic
        fn hash_to_curve(
            messages: &[&[u8]],
            dst: &[u8],
        ) -> Option<generic_ec::NonZero<generic_ec::Point<Self>>>;
    }
}

impl internal::HashToCurve for generic_ec::curves::Secp256k1 {
    fn hash_to_curve(
        messages: &[&[u8]],
        dst: &[u8],
    ) -> Option<generic_ec::NonZero<generic_ec::Point<Self>>> {
        type ExtendedHash = k256::elliptic_curve::hash2curve::ExpandMsgXmd<sha2::Sha256>;
        use k256::elliptic_curve::hash2curve::GroupDigest as _;
        // This can fail if:
        // 1. No domain separation tag is given
        // 2. Output length is zero - impossible
        // 3. Output length is longer than u16::MAX - impossible
        // 4. Output length is grater than 255 * 32 - impossible
        // 5. Output length overflows usize - impossible
        let plain = k256::Secp256k1::hash_from_bytes::<ExtendedHash>(messages, &[dst]).ok()?;
        let plain = generic_ec_curves::rust_crypto::RustCryptoPoint(plain);
        let plain: generic_ec::Point<generic_ec_curves::Secp256k1> =
            generic_ec::as_raw::FromRaw::from_raw(plain);
        // Can fail if point is zero
        generic_ec::NonZero::try_from(plain).ok()
    }
}

fn hash_to_curve<E: internal::HashToCurve>(
    message: &[u8],
    dst: &[u8],
) -> generic_ec::NonZero<generic_ec::Point<E>> {
    for i in 0..=255u8 {
        if let Some(r) = E::hash_to_curve(&[&[i], message], dst) {
            return r;
        }
    }
    #[allow(clippy::panic)]
    {
        panic!("Bad curve or hash algorithm: too many failures");
    }
}

#[cfg(test)]
mod test {
    type E = generic_ec::curves::Secp256k1;

    #[test_case::test_case(3, 5; "t3n5")]
    #[test_case::test_case(5, 5; "t5n5")]
    #[test_case::test_case(3, 7; "t3n7")]
    fn aggregate_same_as_digest(t: u16, n: u16) {
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

        let data = b"take that you worm";
        let eid = b"test";

        let digest = super::digest::<sha2::Sha256, E>(data, &secret_key);
        let partials = shares
            .iter()
            .zip(0..)
            .map(|(s, i)| super::partial_digest::<sha2::Sha256, E>(eid, i, data, &s.x, &mut rng))
            .collect::<Vec<_>>();
        let restored = super::aggregate::<sha2::Sha256, E>(
            eid,
            data,
            &partials[0..t],
            public_shares,
            share_preimages,
        )
        .unwrap();

        assert_eq!(restored, digest);
    }

    #[test_case::test_case(3, 5; "t3n5")]
    #[test_case::test_case(5, 5; "t5n5")]
    #[test_case::test_case(3, 7; "t3n7")]
    fn protocol_same_as_digest(t: u16, n: u16) {
        let mut rng = rand_dev::DevRng::new();

        let secret_key = generic_ec::NonZero::<generic_ec::SecretScalar<E>>::random(&mut rng);
        let shares = key_share::trusted_dealer::builder::<E>(n)
            .set_threshold(Some(t))
            .set_shared_secret_key(secret_key.clone())
            .generate_shares(&mut rng)
            .unwrap();

        let data = b"take that you worm";
        let party_indexes = random_participants(n, t, &mut rng);
        let parties = party_indexes
            .iter()
            .map(|x| u16::try_from(*x).unwrap())
            .collect::<Vec<_>>();

        let digests = round_based::sim::run_with_setup(
            party_indexes.iter().copied(),
            |i, party, party_index| {
                let mut rng = rng.fork();
                let share = &shares[party_index];
                let parties = &parties;
                async move {
                    crate::start_digest::<sha2::Sha256, _, _>(
                        b"test", data, i, share, parties, party, &mut rng,
                    )
                    .await
                }
            },
        )
        .unwrap()
        .expect_ok()
        .into_vec();

        let golden = super::digest::<sha2::Sha256, E>(data, &secret_key);
        for digest in &digests {
            assert_eq!(golden, *digest);
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
