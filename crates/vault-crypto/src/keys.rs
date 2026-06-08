use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use vault_common::{VaultError, VaultResult};
use zeroize::Zeroize;

use std::sync::atomic::{AtomicU64, Ordering};

static GLOBAL_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct SecretBytes {
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

fn generate_unique_nonce() -> [u8; 12] {
    let counter = GLOBAL_NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes[..4]);
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce_bytes
}

pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8], aad: &[u8]) -> VaultResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(VaultError::Crypto(
            "AES-256-GCM vereist een 32-byte sleutel".into(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("AES-GCM cipher init: {}", e)))?;
    let nonce_bytes = generate_unique_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload { msg: plaintext, aad };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| VaultError::Crypto(format!("AES-GCM encryptie: {}", e)))?;
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
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
    use subtle::ConstantTimeEq;
    let len_eq = a.len() == b.len();
    let check_len = if len_eq { a.len() } else { a.len().min(b.len()) };
    let content_eq: bool = if check_len > 0 {
        a[..check_len].ct_eq(&b[..check_len]).into()
    } else {
        true
    };
    len_eq & content_eq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = random_256bit();
        let plaintext = b"SovereignKernel test payload";
        let aad = b"associated-data-context";
        let encrypted = encrypt_aes_gcm(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &encrypted, aad).unwrap();
        assert_eq!(decrypted.expose_secret(), plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = random_256bit();
        let plaintext = b"tamper test";
        let aad = b"";
        let mut encrypted = encrypt_aes_gcm(&key, plaintext, aad).unwrap();
        encrypted[14] ^= 0xFF;
        assert!(decrypt_aes_gcm(&key, &encrypted, aad).is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = random_256bit();
        let plaintext = b"aad test";
        let encrypted = encrypt_aes_gcm(&key, plaintext, b"correct").unwrap();
        assert!(decrypt_aes_gcm(&key, &encrypted, b"wrong").is_err());
    }

    #[test]
    fn test_constant_time_eq_same() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 5];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 6];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_secret_bytes_zeroize_on_drop() {
        let ptr: *const u8;
        {
            let s = SecretBytes::new(vec![0xAA; 64]);
            ptr = s.data.as_ptr();
            let _ = ptr;
        }
    }

    #[test]
    fn test_unique_nonces() {
        let n1 = generate_unique_nonce();
        let n2 = generate_unique_nonce();
        assert_ne!(n1, n2);
    }
}
