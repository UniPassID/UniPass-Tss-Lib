use error::TssError;

pub mod error;
pub mod keygen;
pub mod sign;
mod tests;

pub type TssResult<T> = Result<T, TssError>;

pub use curv;
pub use multi_party_eddsa;
