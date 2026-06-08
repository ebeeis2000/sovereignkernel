pub mod error;
pub use error::*;
pub type VaultResult<T> = Result<T, VaultError>;
