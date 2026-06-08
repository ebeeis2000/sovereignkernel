use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use vault_common::{VaultError, VaultResult};

const MAX_BACKUPS: usize = 5;

pub struct BackupManager {
    data_dir: PathBuf,
    backup_dir: PathBuf,
}

impl BackupManager {
    pub fn new(data_dir: &Path) -> VaultResult<Self> {
        let backup_dir = data_dir.join("backups");
        fs::create_dir_all(&backup_dir)
            .map_err(|e| VaultError::Storage(format!("Kan backup directory niet aanmaken: {}", e)))?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            backup_dir,
        })
    }

    pub fn create_backup(&self) -> VaultResult<PathBuf> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let backup_name = format!("vault_backup_{}", timestamp);
        let backup_path = self.backup_dir.join(&backup_name);

        fs::create_dir_all(&backup_path)
            .map_err(|e| VaultError::Storage(format!("Kan backup map niet aanmaken: {}", e)))?;

        let files_to_backup = [
            "vault.db",
            "audit.db",
            "tpm_state.json",
            "hmac_key.enc",
            "machine_id",
        ];

        let mut manifest = Vec::new();
        for filename in &files_to_backup {
            let src = self.data_dir.join(filename);
            if src.exists() {
                let dst = backup_path.join(filename);
                fs::copy(&src, &dst)
                    .map_err(|e| VaultError::Storage(format!("Backup kopie mislukt voor {}: {}", filename, e)))?;

                let hash = self.compute_file_hash(&dst)?;
                manifest.push(format!("{}  {}", hex::encode(hash), filename));
            }
        }

        let manifest_content = manifest.join("\n");
        fs::write(backup_path.join("MANIFEST.sha256"), &manifest_content)
            .map_err(|e| VaultError::Storage(format!("Manifest schrijven mislukt: {}", e)))?;

        tracing::info!("Backup aangemaakt: {}", backup_path.display());
        self.prune_old_backups()?;

        Ok(backup_path)
    }

    pub fn verify_backup(&self, backup_path: &Path) -> VaultResult<bool> {
        let manifest_path = backup_path.join("MANIFEST.sha256");
        if !manifest_path.exists() {
            return Err(VaultError::Integrity("Backup manifest ontbreekt".into()));
        }

        let manifest = fs::read_to_string(&manifest_path)
            .map_err(|e| VaultError::Storage(format!("Manifest lezen mislukt: {}", e)))?;

        for line in manifest.lines() {
            let parts: Vec<&str> = line.splitn(2, "  ").collect();
            if parts.len() != 2 {
                return Err(VaultError::Integrity(format!("Ongeldig manifest formaat: {}", line)));
            }

            let expected_hex = parts[0];
            let filename = parts[1];
            let file_path = backup_path.join(filename);

            if !file_path.exists() {
                return Err(VaultError::Integrity(format!("Bestand ontbreekt in backup: {}", filename)));
            }

            let actual_hash = self.compute_file_hash(&file_path)?;
            let actual_hex = hex::encode(actual_hash);

            if actual_hex != expected_hex {
                return Err(VaultError::Integrity(format!(
                    "Hash mismatch voor {}: verwacht={}, huidig={}",
                    filename, expected_hex, actual_hex
                )));
            }
        }

        Ok(true)
    }

    pub fn restore_backup(&self, backup_path: &Path) -> VaultResult<()> {
        self.verify_backup(backup_path)?;

        let manifest_path = backup_path.join("MANIFEST.sha256");
        let manifest = fs::read_to_string(&manifest_path)
            .map_err(|e| VaultError::Storage(format!("Manifest lezen mislukt: {}", e)))?;

        for line in manifest.lines() {
            let parts: Vec<&str> = line.splitn(2, "  ").collect();
            if parts.len() != 2 { continue; }
            let filename = parts[1];
            let src = backup_path.join(filename);
            let dst = self.data_dir.join(filename);

            fs::copy(&src, &dst)
                .map_err(|e| VaultError::Storage(format!("Restore mislukt voor {}: {}", filename, e)))?;
        }

        tracing::info!("Backup hersteld van: {}", backup_path.display());
        Ok(())
    }

    pub fn list_backups(&self) -> VaultResult<Vec<PathBuf>> {
        let mut backups: Vec<PathBuf> = fs::read_dir(&self.backup_dir)
            .map_err(|e| VaultError::Storage(format!("Kan backups niet lezen: {}", e)))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir() && e.file_name().to_string_lossy().starts_with("vault_backup_"))
            .map(|e| e.path())
            .collect();

        backups.sort();
        backups.reverse();
        Ok(backups)
    }

    fn prune_old_backups(&self) -> VaultResult<()> {
        let backups = self.list_backups()?;
        if backups.len() > MAX_BACKUPS {
            for old_backup in &backups[MAX_BACKUPS..] {
                tracing::info!("Oude backup verwijderen: {}", old_backup.display());
                fs::remove_dir_all(old_backup)
                    .map_err(|e| VaultError::Storage(format!("Kan oude backup niet verwijderen: {}", e)))?;
            }
        }
        Ok(())
    }

    fn compute_file_hash(&self, path: &Path) -> VaultResult<[u8; 32]> {
        let data = fs::read(path)
            .map_err(|e| VaultError::Storage(format!("Kan bestand niet lezen voor hash: {}", e)))?;
        let hash: [u8; 32] = Sha256::digest(&data).into();
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_backup_and_restore() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();

        fs::write(data_dir.join("vault.db"), b"test vault data").unwrap();
        fs::write(data_dir.join("machine_id"), vec![42u8; 32]).unwrap();

        let mgr = BackupManager::new(&data_dir).unwrap();
        let backup = mgr.create_backup().unwrap();

        assert!(mgr.verify_backup(&backup).unwrap());

        fs::write(data_dir.join("vault.db"), b"modified data").unwrap();

        mgr.restore_backup(&backup).unwrap();
        let restored = fs::read(data_dir.join("vault.db")).unwrap();
        assert_eq!(restored, b"test vault data");
    }

    #[test]
    fn test_backup_pruning() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("vault.db"), b"data").unwrap();

        let mgr = BackupManager::new(&data_dir).unwrap();
        for _ in 0..7 {
            mgr.create_backup().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let backups = mgr.list_backups().unwrap();
        assert!(backups.len() <= MAX_BACKUPS);
    }
}
