/// Error thrown by the server.
#[derive(Debug, thiserror::Error)]
pub enum TssError {
    #[error("error:`{0}`")]
    SpecificError(String),

    /// Error keygen
    #[error("error:`{0}`")]
    EddsaError(#[from] multi_party_eddsa::Error),

    #[error("inputs length unmatch")]
    InputsLengthUnmatch,

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::error::Error),

    #[error(transparent)]
    ProofError(#[from] curv::cryptographic_primitives::proofs::ProofError),
}

#[cfg(feature = "actix_web")]
impl actix_web::ResponseError for TssError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::with_body(self.status_code(), self.to_string())
            .map_into_boxed_body()
    }
}
