use hkdf::Hkdf;
use sha2::Sha256;
use vault_common::{VaultError, VaultResult};

pub struct KeyDeriver {
    ikm: Vec<u8>,
}

impl KeyDeriver {
    pub fn new(ikm: Vec<u8>) -> Self {
        Self { ikm }
    }

    pub fn derive_encryption_key(&self, salt: &[u8], info: &[u8]) -> VaultResult<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| VaultError::Crypto(format!("HKDF expand: {}", e)))?;
        Ok(okm)
    }

    pub fn derive_mac_key(&self, salt: &[u8], info: &[u8]) -> VaultResult<[u8; 32]> {
        self.derive_encryption_key(salt, info)
    }
}

impl Drop for KeyDeriver {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.ikm.zeroize();
    }
}
