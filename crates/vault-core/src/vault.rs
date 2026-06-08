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

#[allow(dead_code)]
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

        let integrity_hmac_key = Self::load_or_create_hmac_key(&config.data_dir)?;

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

    fn load_or_create_hmac_key(data_dir: &Path) -> VaultResult<[u8; 32]> {
        let hmac_path = data_dir.join("hmac_key.enc");
        if hmac_path.exists() {
            let encrypted = std::fs::read(&hmac_path)
                .map_err(|e| VaultError::Storage(format!("Kan HMAC key niet lezen: {}", e)))?;
            Self::dpapi_unprotect(&encrypted)
        } else {
            let key = vault_crypto::keys::random_256bit();
            let protected = Self::dpapi_protect(&key)?;
            std::fs::write(&hmac_path, &protected)
                .map_err(|e| VaultError::Storage(format!("Kan HMAC key niet opslaan: {}", e)))?;
            Ok(key)
        }
    }

    #[cfg(target_os = "windows")]
    fn dpapi_protect(data: &[u8]) -> VaultResult<Vec<u8>> {
        use std::ptr;
        #[repr(C)]
        struct DataBlob { cb_data: u32, pb_data: *const u8 }
        extern "system" {
            fn CryptProtectData(
                pDataIn: *const DataBlob, szDataDescr: *const u16, pOptionalEntropy: *const DataBlob,
                pvReserved: *const u8, pPromptStruct: *const u8, dwFlags: u32, pDataOut: *mut DataBlob,
            ) -> i32;
            fn LocalFree(hMem: *const u8) -> *const u8;
        }
        let entropy = b"SovereignKernel-HMAC-DPAPI-v1";
        let input = DataBlob { cb_data: data.len() as u32, pb_data: data.as_ptr() };
        let ent = DataBlob { cb_data: entropy.len() as u32, pb_data: entropy.as_ptr() };
        let mut output = DataBlob { cb_data: 0, pb_data: ptr::null() };
        let ok = unsafe { CryptProtectData(&input, ptr::null(), &ent, ptr::null(), ptr::null(), 0x04, &mut output) };
        if ok == 0 {
            return Err(VaultError::Crypto("DPAPI CryptProtectData mislukt".into()));
        }
        let result = unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
        unsafe { LocalFree(output.pb_data); }
        Ok(result)
    }

    #[cfg(target_os = "windows")]
    fn dpapi_unprotect(data: &[u8]) -> VaultResult<[u8; 32]> {
        use std::ptr;
        #[repr(C)]
        struct DataBlob { cb_data: u32, pb_data: *const u8 }
        extern "system" {
            fn CryptUnprotectData(
                pDataIn: *const DataBlob, ppszDataDescr: *mut *const u16, pOptionalEntropy: *const DataBlob,
                pvReserved: *const u8, pPromptStruct: *const u8, dwFlags: u32, pDataOut: *mut DataBlob,
            ) -> i32;
            fn LocalFree(hMem: *const u8) -> *const u8;
        }
        let entropy = b"SovereignKernel-HMAC-DPAPI-v1";
        let input = DataBlob { cb_data: data.len() as u32, pb_data: data.as_ptr() };
        let ent = DataBlob { cb_data: entropy.len() as u32, pb_data: entropy.as_ptr() };
        let mut output = DataBlob { cb_data: 0, pb_data: ptr::null() };
        let ok = unsafe { CryptUnprotectData(&input, ptr::null_mut(), &ent, ptr::null(), ptr::null(), 0x04, &mut output) };
        if ok == 0 {
            return Err(VaultError::Crypto("DPAPI CryptUnprotectData mislukt — mogelijke tampering".into()));
        }
        if output.cb_data != 32 {
            unsafe { LocalFree(output.pb_data); }
            return Err(VaultError::Integrity("DPAPI output lengte ongeldig".into()));
        }
        let mut key = [0u8; 32];
        unsafe { key.copy_from_slice(std::slice::from_raw_parts(output.pb_data, 32)); }
        unsafe { LocalFree(output.pb_data); }
        Ok(key)
    }

    #[cfg(not(target_os = "windows"))]
    fn dpapi_protect(data: &[u8]) -> VaultResult<Vec<u8>> {
        let salt = vault_crypto::keys::random_128bit();
        let deriver = vault_crypto::hkdf::KeyDeriver::new(data.to_vec());
        let wrap_key = deriver.derive_encryption_key(&salt, b"SovereignKernel-HMAC-wrap-v1")?;
        let encrypted = vault_crypto::keys::encrypt_aes_gcm(&wrap_key, data, b"hmac-key-storage")?;
        let mut result = salt.to_vec();
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    #[cfg(not(target_os = "windows"))]
    fn dpapi_unprotect(data: &[u8]) -> VaultResult<[u8; 32]> {
        if data.len() < 16 + 28 {
            return Err(VaultError::Integrity("HMAC key bestand te kort".into()));
        }
        let (salt, encrypted) = data.split_at(16);
        let mid_path = std::env::current_dir().unwrap_or_default().join("vault-data").join("machine_id");
        let machine_id = std::fs::read(&mid_path).unwrap_or_else(|_| vec![0u8; 32]);
        let deriver = vault_crypto::hkdf::KeyDeriver::new(machine_id);
        let wrap_key = deriver.derive_encryption_key(salt, b"SovereignKernel-HMAC-wrap-v1")?;
        let decrypted = vault_crypto::keys::decrypt_aes_gcm(&wrap_key, encrypted, b"hmac-key-storage")?;
        if decrypted.len() != 32 {
            return Err(VaultError::Integrity("HMAC key lengte ongeldig".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(decrypted.expose_secret());
        Ok(key)
    }

    pub fn unlock(&mut self, provider: &str, credentials: &[u8]) -> VaultResult<()> {
        self.rate_limiter.check()?;

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
                self.rate_limiter.record_failure()?;
                let remaining = self.rate_limiter.remaining_attempts().unwrap_or(0);
                let an = self.config.max_unlock_attempts.saturating_sub(remaining);
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

    #[allow(dead_code)]
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
        zeroize::Zeroize::zeroize(&mut self.integrity_hmac_key);
    }
}
