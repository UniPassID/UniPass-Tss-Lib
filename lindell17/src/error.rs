//! Error

use curv::cryptographic_primitives::proofs::ProofError;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::PartyTwoError;
use zk_paillier::zkproofs::IncorrectProof;

/// Error thrown by the server.
#[derive(Debug, thiserror::Error)]
pub enum LindellError {
    #[error("error:`{0}`")]
    SpecificError(String),

    #[error("error:`{0}`")]
    RecoverError(String),

    /// Error keygen
    #[error("error:`{0:?}`")]
    KeyGenError(multi_party_ecdsa::Error),

    #[error(transparent)]
    PartyTwoError(#[from] PartyTwoError),

    #[error(transparent)]
    IncorrectProof(#[from] IncorrectProof),

    #[error(transparent)]
    ProofError(#[from] ProofError),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::error::Error),

    #[error(transparent)]
    PointFromBytesError(#[from] curv::elliptic::curves::PointFromBytesError),
}
