#[cfg(test)]
mod rate_limiter_tests {
    use crate::rate_limiter::RateLimiter;
    use tempfile::TempDir;

    fn create_limiter(
        max_attempts: u32,
        window_sec: u64,
        lockout_sec: u64,
    ) -> (RateLimiter, TempDir) {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("rate_limit.db");
        let limiter = RateLimiter::new(db_path, max_attempts, window_sec, lockout_sec).unwrap();
        (limiter, tmp)
    }

    #[test]
    fn test_initial_state_allows_access() {
        let (limiter, _tmp) = create_limiter(5, 300, 900);
        assert!(limiter.check().is_ok());
        assert_eq!(limiter.remaining_attempts().unwrap(), 5);
    }

    #[test]
    fn test_failures_decrement_remaining() {
        let (limiter, _tmp) = create_limiter(5, 300, 900);
        limiter.record_failure().unwrap();
        assert_eq!(limiter.remaining_attempts().unwrap(), 4);
        limiter.record_failure().unwrap();
        assert_eq!(limiter.remaining_attempts().unwrap(), 3);
    }

    #[test]
    fn test_lockout_after_max_attempts() {
        let (limiter, _tmp) = create_limiter(3, 300, 900);
        limiter.record_failure().unwrap();
        limiter.record_failure().unwrap();
        limiter.record_failure().unwrap();
        let result = limiter.check();
        assert!(result.is_err());
    }

    #[test]
    fn test_success_resets_all_failures() {
        let (limiter, _tmp) = create_limiter(5, 300, 900);
        limiter.record_failure().unwrap();
        limiter.record_failure().unwrap();
        assert_eq!(limiter.remaining_attempts().unwrap(), 3);
        limiter.record_success().unwrap();
        assert_eq!(limiter.remaining_attempts().unwrap(), 5);
    }

    #[test]
    fn test_clone_shares_state() {
        let (limiter, _tmp) = create_limiter(5, 300, 900);
        limiter.record_failure().unwrap();
        let cloned = limiter.clone();
        assert_eq!(cloned.remaining_attempts().unwrap(), 4);
    }
}

#[cfg(test)]
mod backup_tests {
    use crate::backup::BackupManager;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_backup_creates_manifest() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("vault.db"), b"encrypted vault data").unwrap();

        let mgr = BackupManager::new(&data_dir).unwrap();
        let backup_path = mgr.create_backup().unwrap();

        assert!(backup_path.join("MANIFEST.sha256").exists());
        assert!(backup_path.join("vault.db").exists());
    }

    #[test]
    fn test_backup_verify_detects_tampering() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("vault.db"), b"original data").unwrap();

        let mgr = BackupManager::new(&data_dir).unwrap();
        let backup_path = mgr.create_backup().unwrap();

        // Tamper with the backup
        fs::write(backup_path.join("vault.db"), b"tampered data").unwrap();

        let result = mgr.verify_backup(&backup_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_backups_ordered() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("vault.db"), b"data").unwrap();

        let mgr = BackupManager::new(&data_dir).unwrap();
        mgr.create_backup().unwrap();
        // Must sleep >1s since timestamp resolution is seconds
        std::thread::sleep(std::time::Duration::from_millis(1100));
        mgr.create_backup().unwrap();

        let backups = mgr.list_backups().unwrap();
        assert_eq!(backups.len(), 2);
        // Most recent first
        assert!(backups[0] > backups[1]);
    }

    #[test]
    fn test_restore_recovers_data() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("vault.db"), b"important secrets").unwrap();

        let mgr = BackupManager::new(&data_dir).unwrap();
        let backup_path = mgr.create_backup().unwrap();

        // Simulate data corruption
        fs::write(data_dir.join("vault.db"), b"corrupted!").unwrap();

        // Restore
        mgr.restore_backup(&backup_path).unwrap();
        let content = fs::read(data_dir.join("vault.db")).unwrap();
        assert_eq!(content, b"important secrets");
    }
}

#[cfg(test)]
mod state_validator_tests {
    use crate::state_validator::StateValidator;

    #[test]
    fn test_valid_state_passes() {
        let mut sv = StateValidator::new();
        let data = b"vault state data";
        sv.set_baseline(data);
        assert!(sv.validate(data).unwrap());
    }

    #[test]
    fn test_tampered_state_fails() {
        let mut sv = StateValidator::new();
        sv.set_baseline(b"vault state data");
        let result = sv.validate(b"vault state tampered");
        assert!(result.is_err());
    }

    #[test]
    fn test_uninitialized_fails() {
        let sv = StateValidator::new();
        let result = sv.validate(b"any data");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_data_valid() {
        let mut sv = StateValidator::new();
        sv.set_baseline(b"");
        assert!(sv.validate(b"").unwrap());
    }
}
