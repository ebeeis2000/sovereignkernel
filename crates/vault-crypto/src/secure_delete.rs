use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use vault_common::{VaultError, VaultResult};

const OVERWRITE_PASSES: usize = 3;

pub fn secure_delete(path: &Path) -> VaultResult<()> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(path)
        .map_err(|e| VaultError::Storage(format!("Kan bestand niet lezen: {}", e)))?;

    let file_size = metadata.len() as usize;
    if file_size == 0 {
        fs::remove_file(path)
            .map_err(|e| VaultError::Storage(format!("Kan leeg bestand niet verwijderen: {}", e)))?;
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| VaultError::Storage(format!("Kan bestand niet openen voor wissen: {}", e)))?;

    let mut rng = rand::rngs::OsRng;
    let mut buf = vec![0u8; file_size.min(65536)];

    for pass in 0..OVERWRITE_PASSES {
        file.seek(SeekFrom::Start(0))
            .map_err(|e| VaultError::Storage(format!("Seek mislukt pass {}: {}", pass, e)))?;

        let mut remaining = file_size;
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            match pass {
                0 => buf[..chunk].fill(0x00),
                1 => buf[..chunk].fill(0xFF),
                _ => rng.fill_bytes(&mut buf[..chunk]),
            }
            file.write_all(&buf[..chunk])
                .map_err(|e| VaultError::Storage(format!("Schrijf mislukt pass {}: {}", pass, e)))?;
            remaining -= chunk;
        }

        file.flush()
            .map_err(|e| VaultError::Storage(format!("Flush mislukt pass {}: {}", pass, e)))?;
        file.sync_all()
            .map_err(|e| VaultError::Storage(format!("Sync mislukt pass {}: {}", pass, e)))?;
    }

    drop(file);

    fs::remove_file(path)
        .map_err(|e| VaultError::Storage(format!("Kan bestand niet verwijderen na wissen: {}", e)))?;

    tracing::debug!("Beveiligd verwijderd: {:?} ({} bytes, {} passes)", path, file_size, OVERWRITE_PASSES);
    Ok(())
}

pub fn secure_delete_dir(dir: &Path) -> VaultResult<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)
        .map_err(|e| VaultError::Storage(format!("Kan directory niet lezen: {}", e)))?
    {
        let entry = entry
            .map_err(|e| VaultError::Storage(format!("Directory entry fout: {}", e)))?;
        let path = entry.path();
        if path.is_dir() {
            secure_delete_dir(&path)?;
        } else {
            secure_delete(&path)?;
        }
    }

    fs::remove_dir(dir)
        .map_err(|e| VaultError::Storage(format!("Kan directory niet verwijderen: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_secure_delete_removes_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"geheim wachtwoord data").unwrap();
        let path = tmp.path().to_path_buf();
        tmp.persist(&path).unwrap();

        assert!(path.exists());
        secure_delete(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_secure_delete_nonexistent_ok() {
        let path = Path::new("/tmp/nonexistent_file_test_sk");
        assert!(secure_delete(path).is_ok());
    }
}
