use round_based::SinkExt as _;

/// Protocol message
#[derive(round_based::ProtocolMessage, Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: generic_ec::Curve> {
    /// The only round
    Partial(MsgPartial<E>),
}

/// Protocol message
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct MsgPartial<E: generic_ec::Curve> {
    /// Partial digest of a party
    pub digest: generic_ec::NonZero<generic_ec::Point<E>>,
}

pub(crate) async fn run<D, E, M>(
    data: &[u8],
    secret_share: &generic_ec::NonZero<generic_ec::SecretScalar<E>>,
    i: u16,
    n: u16,
    share_preimages: Option<&[generic_ec::NonZero<generic_ec::Scalar<E>>]>,
    party: M,
) -> Result<generic_ec::Point<E>, Error>
where
    D: digest::Digest,
    E: super::int::HashToCurve,
    M: round_based::Mpc<ProtocolMessage = Msg<E>>,
{
    let round_based::MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = round_based::Delivery::split(delivery);

    let mut rounds = round_based::rounds_router::RoundsRouter::<Msg<E>>::builder();
    let round =
        rounds.add_round(round_based::rounds_router::simple_store::RoundInput::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    let digest = super::partial_digest::<D, E>(data, secret_share);
    let my_partial = MsgPartial { digest };
    outgoings
        .send(round_based::Outgoing::broadcast(Msg::Partial(
            my_partial.clone(),
        )))
        .await
        .map_err(|e| Error::SendMessage(Box::new(e)))?;

    let partials = rounds
        .complete(round)
        .await
        .map_err(|x| Error::RecvMessage(Box::new(x)))?;
    let partials = partials
        .into_iter_including_me(my_partial)
        .map(|s| s.digest)
        .collect::<Vec<_>>();

    super::aggregate(&partials, share_preimages).ok_or(Error::AggregateFailed)
}

/// Error with a reason for protocol start or execution failure
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Send message error
    #[error("send message")]
    SendMessage(Box<dyn std::error::Error + Send + Sync>),
    /// Receive message error
    #[error("recv message")]
    RecvMessage(Box<dyn std::error::Error + Send + Sync>),
    /// Aggregation failure
    #[error("aggregation failed")]
    AggregateFailed,
    /// Failure to start
    #[error("creating protocol failed")]
    CreationFailed(&'static str),
}
