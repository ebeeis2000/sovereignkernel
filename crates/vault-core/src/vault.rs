use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use vault_audit::{AuditEvent, AuditLogger, LockReason};
use vault_common::{VaultError, VaultResult};
use vault_crypto::keys::SecretBytes;
use vault_tpm::manager::TpmManager;

use super::rate_limiter::RateLimiter;

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub data_dir: PathBuf,
    pub max_unlock_attempts: u32,
    pub unlock_window_seconds: u64,
    pub lockout_duration_seconds: u64,
    pub auto_lock_timeout_seconds: Option<u64>,
    pub shamir_threshold: usize,
    pub shamir_total_shares: usize,
    pub tpm_enabled: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./vault-data"),
            max_unlock_attempts: 5,
            unlock_window_seconds: 300,
            lockout_duration_seconds: 900,
            auto_lock_timeout_seconds: Some(600),
            shamir_threshold: 3,
            shamir_total_shares: 5,
            tpm_enabled: true,
        }
    }
}

pub struct Vault {
    config: VaultConfig,
    rate_limiter: RateLimiter,
    audit_logger: Arc<AuditLogger>,
    tpm_manager: Option<TpmManager>,
    master_key: Option<SecretBytes>,
    is_unlocked: bool,
    last_activity: Option<Instant>,
    integrity_hmac_key: [u8; 32],
    machine_id: [u8; 32],
}

impl Vault {
    pub fn initialize(config: VaultConfig) -> VaultResult<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| VaultError::Storage(format!("Kan data directory niet aanmaken: {}", e)))?;

        let mid_path = config.data_dir.join("machine_id");
        let machine_id = if mid_path.exists() {
            let d = std::fs::read(&mid_path)
                .map_err(|e| VaultError::Storage(format!("Kan machine ID niet lezen: {}", e)))?;
            if d.len() != 32 {
                return Err(VaultError::Integrity("Machine ID corrupt".into()));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&d);
            id
        } else {
            let id = vault_crypto::keys::random_256bit();
            std::fs::write(&mid_path, id)
                .map_err(|e| VaultError::Storage(format!("Kan machine ID niet opslaan: {}", e)))?;
            id
        };

        let hmac_path = config.data_dir.join("hmac_key");
        let integrity_hmac_key = if hmac_path.exists() {
            let d = std::fs::read(&hmac_path)
                .map_err(|e| VaultError::Storage(format!("Kan HMAC key niet lezen: {}", e)))?;
            if d.len() != 32 {
                return Err(VaultError::Integrity("HMAC key corrupt".into()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&d);
            k
        } else {
            let k = vault_crypto::keys::random_256bit();
            std::fs::write(&hmac_path, k)
                .map_err(|e| VaultError::Storage(format!("Kan HMAC key niet opslaan: {}", e)))?;
            k
        };

        let rl = RateLimiter::new(
            config.data_dir.join("ratelimit.db"),
            config.max_unlock_attempts,
            config.unlock_window_seconds,
            config.lockout_duration_seconds,
        )?;

        let al = Arc::new(AuditLogger::new(
            config.data_dir.join("audit.db").to_str().ok_or_else(|| VaultError::Config("Ongeldig audit pad".into()))?,
            machine_id,
            Some(1000),
            Some(1_073_741_824),
        )?);

        let tm = if config.tpm_enabled && TpmManager::is_available() {
            Some(TpmManager::new_with_audit(Some(al.clone()))?)
        } else {
            None
        };

        let v = Self {
            config,
            rate_limiter: rl,
            audit_logger: al,
            tpm_manager: tm,
            master_key: None,
            is_unlocked: false,
            last_activity: None,
            integrity_hmac_key,
            machine_id,
        };

        v.audit_logger.log(AuditEvent::ServiceStarted {
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_hash: [0u8; 32],
        })?;

        Ok(v)
    }

    pub fn unlock(&mut self, provider: &str, credentials: &[u8]) -> VaultResult<()> {
        self.rate_limiter.check()?;
        let rem = self.rate_limiter.remaining_attempts().unwrap_or(0);
        let an = self.config.max_unlock_attempts.saturating_sub(rem) + 1;

        match self.unlock_internal(provider, credentials) {
            Ok(()) => {
                self.rate_limiter.record_success()?;
                self.audit_logger.log(AuditEvent::VaultUnlocked {
                    provider: provider.to_string(),
                    shamir_shares_used: None,
                    tpm_pcr_valid: Some(true),
                })?;
                Ok(())
            }
            Err(e) => {
                self.audit_logger.log(AuditEvent::FailedUnlockAttempt {
                    reason: e.to_string(),
                    attempt_number: an,
                    provider: provider.to_string(),
                })?;
                Err(e)
            }
        }
    }

    fn unlock_internal(&mut self, provider: &str, _creds: &[u8]) -> VaultResult<()> {
        match provider {
            "tpm" => {
                let tpm = self.tpm_manager.as_mut()
                    .ok_or_else(|| VaultError::Tpm("TPM niet beschikbaar".into()))?;
                let tsp = self.config.data_dir.join("tpm_state.db");
                let tss = tsp.to_str().ok_or_else(|| VaultError::Config("Ongeldig pad".into()))?;
                let mk = if Path::new(tss).exists() {
                    let mut s = tpm.load_state(tss, &self.integrity_hmac_key)?;
                    let k = tpm.unseal_with_pcr_validation(&mut s, &self.integrity_hmac_key)?;
                    tpm.update_state(tss, &s)?;
                    k
                } else {
                    let s = tpm.initialize_vault(tss, &self.integrity_hmac_key)?;
                    let mut s = s;
                    let k = tpm.unseal_with_pcr_validation(&mut s, &self.integrity_hmac_key)?;
                    tpm.update_state(tss, &s)?;
                    k
                };
                self.master_key = Some(SecretBytes::new(mk));
            }
            _ => return Err(VaultError::Config(format!("Onbekende provider: {}", provider))),
        }
        self.is_unlocked = true;
        self.last_activity = Some(Instant::now());
        Ok(())
    }

    pub fn lock(&mut self, reason: LockReason) -> VaultResult<()> {
        if !self.is_unlocked {
            return Ok(());
        }
        self.master_key = None;
        self.is_unlocked = false;
        self.last_activity = None;
        self.audit_logger.log(AuditEvent::VaultLocked { reason })?;
        Ok(())
    }

    pub fn check_auto_lock(&mut self) -> VaultResult<()> {
        if !self.is_unlocked {
            return Ok(());
        }
        if let Some(to) = self.config.auto_lock_timeout_seconds {
            if let Some(la) = self.last_activity {
                if la.elapsed().as_secs() > to {
                    return self.lock(LockReason::AutoTimeout);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn touch_activity(&mut self) {
        self.last_activity = Some(Instant::now());
    }

    pub fn master_key(&self) -> VaultResult<&SecretBytes> {
        self.master_key.as_ref().ok_or(VaultError::NotInitialized)
    }

    pub fn is_unlocked(&self) -> bool {
        self.is_unlocked
    }

    pub fn audit_logger(&self) -> &Arc<AuditLogger> {
        &self.audit_logger
    }

    pub fn shutdown(&mut self) -> VaultResult<()> {
        if self.is_unlocked {
            self.lock(LockReason::EmergencyShutdown)?;
        }
        self.audit_logger.log(AuditEvent::ServiceStopped {
            reason: "Shutdown".to_string(),
            uptime_seconds: 0,
        })?;
        Ok(())
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        if self.is_unlocked {
            let _ = self.lock(LockReason::EmergencyShutdown);
        }
    }
}
