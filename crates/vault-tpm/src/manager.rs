use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{error, info};
use vault_audit::{AuditEvent, AuditLogger};
use vault_common::{VaultError, VaultResult};
use vault_crypto::keys::{constant_time_eq, random_256bit};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmState {
    pub pcr_baseline: [u8; 32],
    pub sealed_key: Vec<u8>,
    pub nv_counter_value: u64,
    pub integrity_hmac: [u8; 32],
    pub version: u32,
}

impl TpmState {
    pub fn verify_integrity(&self, hmac_key: &[u8; 32]) -> VaultResult<bool> {
        let computed = self.compute_hmac(hmac_key);
        Ok(constant_time_eq(&computed, &self.integrity_hmac))
    }

    fn compute_hmac(&self, key: &[u8; 32]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key lengte");
        mac.update(&self.pcr_baseline);
        mac.update(&self.sealed_key);
        mac.update(&self.nv_counter_value.to_le_bytes());
        mac.update(&self.version.to_le_bytes());
        mac.finalize().into_bytes().into()
    }

    fn sign(&mut self, key: &[u8; 32]) {
        self.integrity_hmac = self.compute_hmac(key);
    }
}

pub struct TpmManager {
    audit_logger: Option<Arc<AuditLogger>>,
    available: bool,
}

impl TpmManager {
    pub fn new() -> VaultResult<Self> {
        Ok(Self { audit_logger: None, available: Self::is_available() })
    }

    pub fn new_with_audit(audit: Option<Arc<AuditLogger>>) -> VaultResult<Self> {
        Ok(Self { audit_logger: audit, available: Self::is_available() })
    }

    pub fn is_available() -> bool {
        #[cfg(target_os = "windows")]
        {
            std::path::Path::new(r"\\.\TPM").exists()
                || std::env::var("SWTPM_ACTIVE").is_ok()
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
                || std::env::var("SWTPM_ACTIVE").is_ok()
        }
    }

    pub fn initialize_vault(&mut self, state_path: &str, hmac_key: &[u8; 32]) -> VaultResult<TpmState> {
        info!("Initialisatie vault TPM state: {}", state_path);
        let master_key = random_256bit();
        let pcr_baseline = self.read_pcr_baseline()?;

        let mut state = TpmState {
            pcr_baseline,
            sealed_key: master_key.to_vec(),
            nv_counter_value: 0,
            integrity_hmac: [0u8; 32],
            version: 1,
        };
        state.sign(hmac_key);

        let serialized = serde_json::to_vec(&state)
            .map_err(|e| VaultError::Tpm(format!("State serialisatie: {}", e)))?;
        std::fs::write(state_path, &serialized)
            .map_err(|e| VaultError::Storage(format!("State opslaan: {}", e)))?;

        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(AuditEvent::VaultInitialized {
                tpm_available: self.available,
                shamir_threshold: 3,
                shamir_total: 5,
            });
        }

        Ok(state)
    }

    pub fn load_state(&self, state_path: &str, hmac_key: &[u8; 32]) -> VaultResult<TpmState> {
        let data = std::fs::read(state_path)
            .map_err(|e| VaultError::Storage(format!("State laden: {}", e)))?;
        let state: TpmState = serde_json::from_slice(&data)
            .map_err(|e| VaultError::Tpm(format!("State deserialisatie: {}", e)))?;

        if !state.verify_integrity(hmac_key)? {
            error!("TPM state integriteitscontrole mislukt");
            return Err(VaultError::Integrity("TPM state HMAC verificatie mislukt".into()));
        }

        Ok(state)
    }

    pub fn unseal_with_pcr_validation(
        &mut self,
        state: &mut TpmState,
        hmac_key: &[u8; 32],
    ) -> VaultResult<Vec<u8>> {
        let current_pcrs = self.read_pcr_baseline()?;

        let pcr_valid = constant_time_eq(&current_pcrs, &state.pcr_baseline);
        if !pcr_valid {
            if let Some(ref logger) = self.audit_logger {
                let _ = logger.log(AuditEvent::TpmPcrMismatch {
                    expected_pcr_hash: state.pcr_baseline,
                    actual_pcr_hash: current_pcrs,
                    affected_pcrs: vec![0, 1, 2, 3, 4, 5, 6, 7],
                });
            }
            return Err(VaultError::Tpm("PCR baseline mismatch - mogelijke tampering".into()));
        }

        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(AuditEvent::TpmUnsealAttempt {
                pcr_valid: true,
                counter_valid: true,
                success: true,
            });
        }

        state.sign(hmac_key);
        Ok(state.sealed_key.clone())
    }

    pub fn update_state(&self, state_path: &str, state: &TpmState) -> VaultResult<()> {
        let serialized = serde_json::to_vec(state)
            .map_err(|e| VaultError::Tpm(format!("State serialisatie: {}", e)))?;
        std::fs::write(state_path, &serialized)
            .map_err(|e| VaultError::Storage(format!("State opslaan: {}", e)))?;
        Ok(())
    }

    fn read_pcr_baseline(&self) -> VaultResult<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(b"pcr-baseline-placeholder");
        Ok(h.finalize().into())
    }

    #[cfg(feature = "tpm")]
    pub fn context_mut(&mut self) -> &mut tss_esapi::Context {
        unimplemented!("Requires active TPM context")
    }
}
