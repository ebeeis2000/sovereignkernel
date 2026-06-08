use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use vault_common::{VaultError, VaultResult};
use zeroize::Zeroize;

const ARGON2_SALT_LEN: usize = 32;
const ARGON2_MEMORY_KIB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 32;

#[derive(Clone)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        }
    }
}

pub struct DerivedKey {
    pub key: [u8; ARGON2_OUTPUT_LEN],
    pub salt: [u8; ARGON2_SALT_LEN],
    pub params: Argon2Params,
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
    }
}

pub fn derive_key_argon2id(password: &[u8], params: &Argon2Params) -> VaultResult<DerivedKey> {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    derive_key_argon2id_with_salt(password, &salt, params)
}

pub fn derive_key_argon2id_with_salt(
    password: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
    params: &Argon2Params,
) -> VaultResult<DerivedKey> {
    if password.is_empty() {
        return Err(VaultError::Validation(
            "Wachtwoord mag niet leeg zijn".into(),
        ));
    }

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| VaultError::Crypto(format!("Argon2 parameters ongeldig: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key = [0u8; ARGON2_OUTPUT_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| VaultError::Crypto(format!("Argon2id afleiding mislukt: {}", e)))?;

    Ok(DerivedKey {
        key,
        salt: *salt,
        params: params.clone(),
    })
}

pub fn verify_key_argon2id(
    password: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
    expected_key: &[u8; ARGON2_OUTPUT_LEN],
    params: &Argon2Params,
) -> VaultResult<bool> {
    let derived = derive_key_argon2id_with_salt(password, salt, params)?;
    Ok(super::keys::constant_time_eq(&derived.key, expected_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derive_and_verify() {
        let password = b"TestWachtwoord123!";
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let derived = derive_key_argon2id(password, &params).unwrap();
        assert_eq!(derived.key.len(), 32);

        let verified = verify_key_argon2id(password, &derived.salt, &derived.key, &params).unwrap();
        assert!(verified);

        let wrong = verify_key_argon2id(b"fout", &derived.salt, &derived.key, &params).unwrap();
        assert!(!wrong);
    }

    #[test]
    fn test_argon2id_deterministic_with_same_salt() {
        let password = b"ConsistentWachtwoord";
        let salt = [42u8; ARGON2_SALT_LEN];
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let d1 = derive_key_argon2id_with_salt(password, &salt, &params).unwrap();
        let d2 = derive_key_argon2id_with_salt(password, &salt, &params).unwrap();
        assert_eq!(d1.key, d2.key);
    }

    #[test]
    fn test_argon2id_empty_password_rejected() {
        let params = Argon2Params::default();
        let result = derive_key_argon2id(b"", &params);
        assert!(result.is_err());
    }
}
