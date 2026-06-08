use std::fs;
use std::path::{Path, PathBuf};
use vault_common::{VaultError, VaultResult};

use super::db_encryption::{is_database_encrypted, open_encrypted_database, DatabaseKey};

#[derive(Debug)]
pub struct MigrationResult {
    pub original_path: PathBuf,
    pub backup_path: PathBuf,
    pub encrypted_path: PathBuf,
    pub tables_migrated: usize,
    pub rows_migrated: usize,
    pub success: bool,
    pub error: Option<String>,
}

pub fn migrate_to_encrypted(db_path: &Path, key: &DatabaseKey) -> VaultResult<MigrationResult> {
    let original_path = db_path.to_path_buf();
    let backup_path = db_path.with_extension("db.backup");
    let encrypted_path = db_path.with_extension("db.encrypted");

    tracing::info!("Start database migratie: {} -> SQLCipher", db_path.display());

    if backup_path.exists() {
        fs::remove_file(&backup_path)
            .map_err(|e| VaultError::Storage(format!("Kan bestaande backup niet verwijderen: {}", e)))?;
    }

    fs::copy(&original_path, &backup_path)
        .map_err(|e| VaultError::Storage(format!("Kan backup niet maken: {}", e)))?;

    let src_conn = rusqlite::Connection::open(&original_path).map_err(|e| {
        let _ = fs::copy(&backup_path, &original_path);
        VaultError::Storage(format!("Kan originele database niet openen: {}", e))
    })?;

    let tables: Vec<String> = {
        let mut stmt = src_conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            .map_err(|e| VaultError::Storage(format!("Kan tabellen niet lezen: {}", e)))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| VaultError::Storage(format!("Query fout: {}", e)))?;
        let mut names = Vec::new();
        for row in rows {
            names.push(row.map_err(|e| VaultError::Storage(format!("Rij fout: {}", e)))?);
        }
        names
    };

    let mut original_row_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for table in &tables {
        let count: usize = src_conn
            .query_row(&format!("SELECT count(*) FROM \"{}\"", table), [], |row| row.get(0))
            .unwrap_or(0);
        original_row_counts.insert(table.clone(), count);
    }

    if encrypted_path.exists() {
        fs::remove_file(&encrypted_path).ok();
    }

    let mut dst_conn = open_encrypted_database(
        encrypted_path.to_str().ok_or_else(|| VaultError::Storage("Ongeldig pad".into()))?,
        key,
        true,
    )
    .map_err(|e| {
        let _ = fs::copy(&backup_path, &original_path);
        VaultError::Storage(format!("Kan versleutelde database niet aanmaken: {}", e))
    })?;

    {
        let backup = rusqlite::backup::Backup::new(&src_conn, &mut dst_conn)
            .map_err(|e| VaultError::Storage(format!("Backup API fout: {}", e)))?;
        backup
            .run_to_completion(100, std::time::Duration::from_millis(250), None)
            .map_err(|e| VaultError::Storage(format!("Backup uitvoering fout: {}", e)))?;
    }

    let mut total_rows = 0;
    for table in &tables {
        let count: usize = dst_conn
            .query_row(&format!("SELECT count(*) FROM \"{}\"", table), [], |row| row.get(0))
            .unwrap_or(0);
        let original = original_row_counts.get(table).copied().unwrap_or(0);
        if count != original {
            let _ = fs::copy(&backup_path, &original_path);
            return Err(VaultError::Integrity(format!(
                "Data mismatch na migratie: tabel '{}' heeft {} rijen (verwacht {})",
                table, count, original
            )));
        }
        total_rows += count;
    }

    Ok(MigrationResult {
        original_path,
        backup_path,
        encrypted_path,
        tables_migrated: tables.len(),
        rows_migrated: total_rows,
        success: true,
        error: None,
    })
}

pub fn needs_migration(db_path: &Path) -> VaultResult<bool> {
    if !db_path.exists() {
        return Ok(false);
    }
    match db_path.to_str() {
        Some(path_str) => is_database_encrypted(path_str).map(|encrypted| !encrypted),
        None => Err(VaultError::Storage("Ongeldig database pad".into())),
    }
}
