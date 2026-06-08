use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use vault_common::{VaultError, VaultResult};
use zeroize::Zeroize;

#[derive(Zeroize)]
pub struct SecretBytes {
    #[zeroize(skip)]
    data: Vec<u8>,
}

impl SecretBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

pub fn random_key_32() -> SecretBytes {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    SecretBytes::new(key)
}

pub fn random_key(length: usize) -> SecretBytes {
    let mut key = vec![0u8; length];
    OsRng.fill_bytes(&mut key);
    SecretBytes::new(key)
}

pub fn random_256bit() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_128bit() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8], aad: &[u8]) -> VaultResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(VaultError::Crypto(
            "AES-256-GCM vereist een 32-byte sleutel".into(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("AES-GCM cipher init: {}", e)))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload { msg: plaintext, aad };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| VaultError::Crypto(format!("AES-GCM encryptie: {}", e)))?;
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_aes_gcm(key: &[u8], ciphertext_with_nonce: &[u8], aad: &[u8]) -> VaultResult<SecretBytes> {
    if key.len() != 32 {
        return Err(VaultError::Crypto(
            "AES-256-GCM vereist een 32-byte sleutel".into(),
        ));
    }
    if ciphertext_with_nonce.len() < 28 {
        return Err(VaultError::Crypto(
            "Ciphertext te kort: minimaal 28 bytes vereist (12 nonce + 16 tag)".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("AES-GCM cipher init: {}", e)))?;
    let payload = Payload { msg: ciphertext, aad };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| VaultError::Crypto(format!("AES-GCM decryptie/authenticatie: {}", e)))?;
    Ok(SecretBytes::new(plaintext))
}

#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
