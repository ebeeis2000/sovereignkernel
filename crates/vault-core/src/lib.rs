pub mod backup;
pub mod db_encryption;
pub mod db_key_service;
pub mod db_migration;
pub mod rate_limiter;
pub mod state_validator;
pub mod vault;

#[cfg(test)]
mod tests;

pub use backup::BackupManager;
pub use db_encryption::{apply_sqlcipher_pragmas, is_database_encrypted, open_encrypted_database, DatabaseKey};
pub use db_key_service::DbKeyService;
pub use db_migration::{migrate_to_encrypted, needs_migration, MigrationResult};
pub use rate_limiter::RateLimiter;
pub use vault::{Vault, VaultConfig};
