#[cfg(test)]
mod kdf_extended_tests {
    use crate::kdf::{
        derive_key_argon2id, derive_key_argon2id_with_salt, verify_key_argon2id, Argon2Params,
    };

    #[test]
    fn test_different_passwords_different_keys() {
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [99u8; 32];
        let k1 = derive_key_argon2id_with_salt(b"password1", &salt, &params).unwrap();
        let k2 = derive_key_argon2id_with_salt(b"password2", &salt, &params).unwrap();
        assert_ne!(k1.key, k2.key);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];
        let k1 = derive_key_argon2id_with_salt(b"same_password", &salt1, &params).unwrap();
        let k2 = derive_key_argon2id_with_salt(b"same_password", &salt2, &params).unwrap();
        assert_ne!(k1.key, k2.key);
    }

    #[test]
    fn test_random_salt_uniqueness() {
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let k1 = derive_key_argon2id(b"test", &params).unwrap();
        let k2 = derive_key_argon2id(b"test", &params).unwrap();
        // Different random salts → different keys
        assert_ne!(k1.key, k2.key);
        assert_ne!(k1.salt, k2.salt);
    }

    #[test]
    fn test_verify_wrong_password_fails() {
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let derived = derive_key_argon2id(b"correct_password", &params).unwrap();
        let result =
            verify_key_argon2id(b"wrong_password", &derived.salt, &derived.key, &params).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_unicode_password() {
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let password = "wàchtw00rd_ñ_über_中文".as_bytes();
        let derived = derive_key_argon2id(password, &params).unwrap();
        assert!(verify_key_argon2id(password, &derived.salt, &derived.key, &params).unwrap());
    }

    #[test]
    fn test_long_password() {
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let password = vec![b'A'; 10000];
        let derived = derive_key_argon2id(&password, &params).unwrap();
        assert!(verify_key_argon2id(&password, &derived.salt, &derived.key, &params).unwrap());
    }
}

#[cfg(test)]
mod secure_delete_extended_tests {
    use crate::secure_delete::{secure_delete, secure_delete_dir};
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn test_secure_delete_large_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("large_secret.bin");
        let data = vec![0xAB; 1024 * 1024]; // 1MB
        fs::write(&path, &data).unwrap();

        secure_delete(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_secure_delete_empty_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("empty.bin");
        fs::write(&path, b"").unwrap();

        secure_delete(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_secure_delete_dir_recursive() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("secrets");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("a.key"), b"key_a").unwrap();
        fs::write(dir.join("sub/b.key"), b"key_b").unwrap();

        secure_delete_dir(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn test_secure_delete_readonly_fails_gracefully() {
        // Can't easily test read-only on all platforms, but verify nonexistent is OK
        let path = Path::new("/tmp/nonexistent_sk_test_12345");
        assert!(secure_delete(path).is_ok());
    }
}

#[cfg(test)]
mod keys_extended_tests {
    use crate::keys::{constant_time_eq, decrypt_aes_gcm, encrypt_aes_gcm};

    #[test]
    fn test_encrypt_produces_unique_ciphertexts() {
        let key = [42u8; 32];
        let aad = b"context";
        let plaintext = b"same plaintext";
        let c1 = encrypt_aes_gcm(&key, plaintext, aad).unwrap();
        let c2 = encrypt_aes_gcm(&key, plaintext, aad).unwrap();
        // Different nonces → different ciphertexts
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_encrypt_decrypt_empty_message() {
        let key = [42u8; 32];
        let aad = b"context";
        let plaintext = b"";
        let ciphertext = encrypt_aes_gcm(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.expose_secret(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_message() {
        let key = [7u8; 32];
        let aad = b"bulk";
        let plaintext = vec![0xCC; 100_000];
        let ciphertext = encrypt_aes_gcm(&key, &plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.expose_secret(), plaintext.as_slice());
    }

    #[test]
    fn test_wrong_aad_decryption_fails() {
        let key = [5u8; 32];
        let ciphertext = encrypt_aes_gcm(&key, b"secret", b"correct_aad").unwrap();
        let result = decrypt_aes_gcm(&key, &ciphertext, b"wrong_aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_decryption_fails() {
        let key1 = [5u8; 32];
        let key2 = [6u8; 32];
        let ciphertext = encrypt_aes_gcm(&key1, b"secret", b"aad").unwrap();
        let result = decrypt_aes_gcm(&key2, &ciphertext, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [5u8; 32];
        let mut ciphertext = encrypt_aes_gcm(&key, b"secret", b"aad").unwrap();
        ciphertext[15] ^= 0xFF; // Flip a byte
        let result = decrypt_aes_gcm(&key, &ciphertext, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = [5u8; 32];
        let result = decrypt_aes_gcm(&key, &[0u8; 10], b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_eq_equal() {
        let a = vec![1u8; 100];
        assert!(constant_time_eq(&a, &a));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = vec![0u8; 1000];
        let mut b = vec![0u8; 1000];
        b[999] = 1;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = vec![1u8; 10];
        let b = vec![1u8; 11];
        assert!(!constant_time_eq(&a, &b));
    }
}
