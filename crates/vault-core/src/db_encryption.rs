use vault_common::{VaultError, VaultResult};
use vault_crypto::hkdf::KeyDeriver;

#[derive(Clone)]
pub struct DatabaseKey {
    key: [u8; 32],
}

impl DatabaseKey {
    pub fn from_master_key(master_key: &[u8], db_name: &str) -> VaultResult<Self> {
        if master_key.len() != 32 {
            return Err(VaultError::Crypto(
                "Master key moet 32 bytes zijn voor database encryptie".into(),
            ));
        }
        let deriver = KeyDeriver::new(master_key.to_vec());
        let derived = deriver.derive_encryption_key(
            b"SovereignKernel-DB-Encryption-v1",
            format!("db:{}", db_name).as_bytes(),
        )?;
        Ok(Self { key: derived })
    }

    pub fn from_raw(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.key)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for DatabaseKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

impl std::fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseKey").finish_non_exhaustive()
    }
}

pub fn apply_sqlcipher_pragmas(conn: &rusqlite::Connection, key: &DatabaseKey) -> VaultResult<()> {
    let hex_key = key.to_hex();
    let pragma_key = format!("PRAGMA key = \"x'{}'\";\n", hex_key);
    conn.execute_batch(&pragma_key).map_err(|e| {
        VaultError::Crypto(format!(
            "SQLCipher: kan encryptiesleutel niet instellen: {}",
            e
        ))
    })?;

    conn.execute_batch(
        "PRAGMA cipher_page_size = 4096;
         PRAGMA kdf_iter = 256000;
         PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
         PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
         PRAGMA cipher_memory_security = ON;",
    )
    .map_err(|e| {
        VaultError::Crypto(format!(
            "SQLCipher: kan cipher parameters niet configureren: {}",
            e
        ))
    })?;

    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| {
            VaultError::Crypto(
                "SQLCipher: sleutel verificatie mislukt — database kan niet ontsleuteld worden"
                    .into(),
            )
        })?;

    tracing::info!("SQLCipher PRAGMA's toegepast en geverifieerd");
    Ok(())
}

pub fn open_encrypted_database(
    path: &str,
    key: &DatabaseKey,
    create: bool,
) -> VaultResult<rusqlite::Connection> {
    if create && !std::path::Path::new(path).exists() {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| VaultError::Storage(format!("Kan directory niet aanmaken: {}", e)))?;
        }
    }
    let conn = rusqlite::Connection::open(path)
        .map_err(|e| VaultError::Storage(format!("Kan database niet openen '{}': {}", path, e)))?;
    apply_sqlcipher_pragmas(&conn, key)?;
    Ok(conn)
}

pub fn is_database_encrypted(path: &str) -> VaultResult<bool> {
    let conn = rusqlite::Connection::open(path)
        .map_err(|e| VaultError::Storage(format!("Kan database niet openen: {}", e)))?;
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(())) {
        Ok(_) => Ok(false),
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("encrypted") || msg.contains("not a database") {
                Ok(true)
            } else {
                Err(VaultError::Storage(format!(
                    "Kan database status niet bepalen: {}",
                    e
                )))
            }
        }
    }
}
