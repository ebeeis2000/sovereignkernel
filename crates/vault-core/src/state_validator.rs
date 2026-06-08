use sha2::{Digest, Sha256};
use vault_common::{VaultError, VaultResult};
use vault_crypto::keys::constant_time_eq;

pub struct StateValidator {
    expected_hash: Option<[u8; 32]>,
}

impl StateValidator {
    pub fn new() -> Self {
        Self {
            expected_hash: None,
        }
    }

    pub fn set_baseline(&mut self, data: &[u8]) {
        let hash: [u8; 32] = Sha256::digest(data).into();
        self.expected_hash = Some(hash);
    }

    pub fn validate(&self, data: &[u8]) -> VaultResult<bool> {
        let current: [u8; 32] = Sha256::digest(data).into();
        match self.expected_hash {
            Some(expected) => {
                if constant_time_eq(&current, &expected) {
                    Ok(true)
                } else {
                    Err(VaultError::Integrity("State hash mismatch".into()))
                }
            }
            None => Err(VaultError::NotInitialized),
        }
    }
}

impl Default for StateValidator {
    fn default() -> Self {
        Self::new()
    }
}
