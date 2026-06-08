pub mod backup;
pub mod rate_limiter;
pub mod state_validator;
pub mod vault;
pub mod db_encryption;
pub mod db_migration;
pub mod db_key_service;

pub use backup::BackupManager;
pub use rate_limiter::RateLimiter;
pub use vault::{Vault, VaultConfig};
pub use db_encryption::{DatabaseKey, open_encrypted_database, is_database_encrypted, apply_sqlcipher_pragmas};
pub use db_migration::{migrate_to_encrypted, needs_migration, MigrationResult};
pub use db_key_service::DbKeyService;
