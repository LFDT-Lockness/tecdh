//! This crate implements digesting into elliptic curve points keyed with a
//! secret scalar for this curve. This digest resembles BLS signatures, but
//! because we don't do signature verification, we're not limited in the choice
//! of curves. The procedure for a digest is as follows:
//!
//! 1. Input parameters:
//!     * `D` - cryptographic hash function
//!     * `E` - an elliptic curve
//!     * `m` - message to digest, given as a byte string
//!     * `x` - secret key, given as a scalar for `E`
//! 2. Create `HPRng` - a pseudo-random number generator based on `D` and `m`,
//!    with a procedure described in
//!    [`hash_rng`](https://docs.rs/rand_hash/0.1.1/rand_hash/index.html)
//! 3. Generate random `s` from `HPRng` by using a procedure defined for this
//!    curve
//! 4. If `s` is zero, retry from step *3*. If `s` is zero after 100 attempts,
//!    abort
//! 5. Compute `generator(E) * s * x`

pub mod mpc;

/// Compute digest of `data` keyed with `secret_key`
pub fn digest<D: digest::Digest, E: generic_ec::Curve>(
    data: &[u8],
    secret_key: &generic_ec::NonZero<generic_ec::SecretScalar<E>>,
) -> generic_ec::Point<E> {
    let plain_scalar = generic_ec::Scalar::<E>::from_hash::<D>(&data);
    let plain = generic_ec::Point::generator() * plain_scalar;
    plain * secret_key
}

/// Compute partial digest of `data` keyed with a key of which `secret_share` is a
/// share of. Use [`aggregate`] to aggregate multiple partial digests into a full
/// digest
///
/// Partial digest is exactly the same as a full digest; this is a convenient
/// alias if you want to distinguish the functionality in your code.
pub fn partial_digest<D: digest::Digest, E: generic_ec::Curve>(
    data: &[u8],
    secret_share: &generic_ec::NonZero<generic_ec::SecretScalar<E>>,
) -> generic_ec::Point<E> {
    digest::<D, E>(data, secret_share)
}

/// Aggregate `partials` - partial digest values - into a full value.
///
/// `share_preimages` should be `None` for additive key shares. For SSS, it
/// gives the points at which the keyshare values are computed, and should be in
/// the same order by participant as `partials`.
pub fn aggregate<E: generic_ec::Curve>(
    partials: &[generic_ec::Point<E>],
    share_preimages: Option<&[generic_ec::NonZero<generic_ec::Scalar<E>>]>,
) -> Option<generic_ec::Point<E>> {
    if let Some(share_preimages) = share_preimages {
        // shamir aggregation
        let lagrange_coefficients = (0..(share_preimages.len()))
            .map(|j| generic_ec_zkp::polynomial::lagrange_coefficient_at_zero(j, share_preimages))
            .collect::<Option<Vec<_>>>()?;
        Some(generic_ec::Scalar::multiscalar_mul(
            lagrange_coefficients.into_iter().zip(partials),
        ))
    } else {
        // additive aggregation
        Some(partials.iter().sum())
    }
}

/// Start an MPC protocol that digests the data with shared private key. Returns
/// digested data
///
/// - `data` - byte string to digest
/// - `i` - index of party in this protocol invocation, used for message routing
/// - `key_share` - key share to use, can be additive or SSS
/// - `participants` - which key holders are participating in the protocol,
///   given as indexes into `share_preimages` in key share. Ignored for additive
///   shares.
/// - `party` - the `round-based` party
pub async fn start_digest<D, E, M>(
    data: &[u8],
    i: u16,
    key_share: &key_share::CoreKeyShare<E>,
    participants: &[u16],
    party: M,
) -> Result<generic_ec::Point<E>, mpc::Error>
where
    D: digest::Digest,
    E: generic_ec::Curve,
    M: round_based::Mpc<ProtocolMessage = mpc::Msg<E>>,
{
    let share_preimages = match key_share.vss_setup.as_ref() {
        None => None,
        Some(vss_setup) => Some(
            participants
                .iter()
                .map(|i| vss_setup.I.get(usize::from(*i)).copied())
                .collect::<Option<Vec<_>>>()
                .ok_or(mpc::Error::CreationFailed("share is not SSS"))?,
        ),
    };
    let share_preimages = share_preimages.as_ref().map(|v| v.as_ref());

    mpc::run::<D, E, M>(
        data,
        &key_share.x,
        i,
        key_share.min_signers(),
        share_preimages,
        party,
    )
    .await
}

#[cfg(test)]
mod test {
    type E = generic_ec::curves::Ed25519;

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
        let share_preimages = shares[0].vss_setup.as_ref().map(|vss| &vss.I[0..t]);

        let data = b"take that you worm";

        let digest = super::digest::<sha2::Sha256, E>(data, &secret_key);
        let partials = shares
            .iter()
            .map(|s| super::partial_digest::<sha2::Sha256, E>(data, &s.x))
            .collect::<Vec<_>>();
        let restored = super::aggregate(&partials[0..t], share_preimages).unwrap();

        assert_eq!(restored, digest);
    }

    #[test_case::test_case(3, 5; "t3n5")]
    #[test_case::test_case(5, 5; "t5n5")]
    #[test_case::test_case(3, 7; "t3n7")]
    #[tokio::test]
    async fn protocol_same_as_digest(t: u16, n: u16) {
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

        let mut simulation = round_based::simulation::Simulation::<crate::mpc::Msg<E>>::new();
        let mut outputs = vec![];

        for (party_index, i) in party_indexes.iter().copied().zip(0..) {
            let share = &shares[party_index];
            let party = simulation.add_party();
            let parties = &parties; // to prevent it being moved into async closure

            outputs.push(async move {
                crate::start_digest::<sha2::Sha256, _, _>(data, i, share, parties, party).await
            });
        }
        let digests = futures::future::try_join_all(outputs).await.unwrap();

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
