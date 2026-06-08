use vault_common::{VaultError, VaultResult};
use vault_crypto::keys::SecretBytes;

use super::db_encryption::DatabaseKey;

pub struct DbKeyService {
    master_key: Option<SecretBytes>,
}

impl DbKeyService {
    pub fn new() -> Self {
        Self { master_key: None }
    }

    pub fn initialize(&mut self, master_key: SecretBytes) {
        self.master_key = Some(master_key);
    }

    pub fn derive_database_key(&self, db_name: &str) -> VaultResult<DatabaseKey> {
        let mk = self.master_key.as_ref().ok_or(VaultError::NotInitialized)?;
        DatabaseKey::from_master_key(mk.expose_secret(), db_name)
    }

    pub fn is_initialized(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn clear(&mut self) {
        self.master_key = None;
    }
}

impl Default for DbKeyService {
    fn default() -> Self {
        Self::new()
    }
}
