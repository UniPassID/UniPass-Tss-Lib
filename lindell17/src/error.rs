//! Error

use std::string::FromUtf8Error;

use aws_sdk_kms::{
    error::{DecryptError, EncryptError},
    types::SdkError,
};
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
    Base64Error(#[from] base64::DecodeError),

    #[error(transparent)]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error(transparent)]
    EncryptError(#[from] SdkError<EncryptError>),

    #[error(transparent)]
    DecryptError(#[from] SdkError<DecryptError>),

    #[error(transparent)]
    PointFromBytesError(#[from] curv::elliptic::curves::PointFromBytesError),
}

#[cfg(feature = "actix_web")]
impl actix_web::ResponseError for LindellError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::with_body(self.status_code(), self.to_string())
            .map_into_boxed_body()
    }
}
