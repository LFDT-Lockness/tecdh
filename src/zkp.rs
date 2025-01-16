const TAG: &str = "bls-style-digest.zkp";

#[derive(Debug, Clone, udigest::Digestable)]
pub struct SharedState<'a> {
    pub eid: &'a [u8],
    pub prover_index: u16,
}

#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct Data<E: generic_ec::Curve> {
    pub pub_share: generic_ec::Point<E>,
    pub base: generic_ec::Point<E>,
    pub value: generic_ec::Point<E>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct Proof<E: generic_ec::Curve> {
    pub ch: generic_ec::Scalar<E>,
    pub res: generic_ec::Scalar<E>,
}

pub fn prove<D: digest::Digest, E: generic_ec::Curve>(
    shared_state: &impl udigest::Digestable,
    share: &generic_ec::SecretScalar<E>,
    data: Data<E>,
    r: generic_ec::Scalar<E>,
) -> Proof<E> {
    let com1 = generic_ec::Point::generator() * r;
    let com2 = data.base * r;

    let seed = udigest::inline_struct!(TAG {
        shared_state,
        data,
        com1,
        com2,
    });
    let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
    let ch = generic_ec::Scalar::random(&mut rng);

    let res = r + share * ch;
    Proof { ch, res }
}

pub fn verify<D: digest::Digest, E: generic_ec::Curve>(
    shared_state: &impl udigest::Digestable,
    data: Data<E>,
    proof: Proof<E>,
) -> Result<(), InvalidProof> {
    let com1 = generic_ec::Point::generator() * proof.res - data.pub_share * proof.ch;
    let com2 = data.base * proof.res - data.value * proof.ch;

    let seed = udigest::inline_struct!(TAG {
        shared_state,
        data,
        com1,
        com2,
    });
    let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
    let ch = generic_ec::Scalar::random(&mut rng);

    if ch != proof.ch {
        Err(InvalidProof)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub struct InvalidProof;

#[cfg(test)]
mod test {
    fn passing_test<E: generic_ec::Curve, D: digest::Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let shared_state = "shared state";

        let secret_share = generic_ec::SecretScalar::random(&mut rng);
        let public_share = generic_ec::Point::generator() * &secret_share;

        let raw_digest = generic_ec::Point::generator() * generic_ec::Scalar::random(&mut rng);
        let digest = raw_digest * &secret_share;

        let r = generic_ec::Scalar::random(&mut rng);
        let data = super::Data {
            pub_share: public_share,
            base: raw_digest,
            value: digest,
        };
        let proof = super::prove::<D, E>(&shared_state, &secret_share, data, r);
        super::verify::<D, E>(&shared_state, data, proof).unwrap();
    }

    fn failing_test<E: generic_ec::Curve, D: digest::Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let shared_state = "shared state";

        let secret_share = generic_ec::SecretScalar::random(&mut rng);
        let public_share = generic_ec::Point::generator() * &secret_share;

        let raw_digest = generic_ec::Point::generator() * generic_ec::Scalar::random(&mut rng);
        // fake digest is our concern
        let digest = generic_ec::Point::generator() * generic_ec::Scalar::random(&mut rng);

        let r = generic_ec::Scalar::random(&mut rng);
        let data = super::Data {
            pub_share: public_share,
            base: raw_digest,
            value: digest,
        };
        let proof = super::prove::<D, E>(&shared_state, &secret_share, data, r);
        assert!(super::verify::<D, E>(&shared_state, data, proof).is_err());
    }

    #[test]
    fn passing_k256_sha256() {
        passing_test::<generic_ec::curves::Secp256k1, sha2::Sha256>();
    }

    #[test]
    fn failing_k256_sha256() {
        failing_test::<generic_ec::curves::Secp256k1, sha2::Sha256>();
    }
}
