use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Cryptografische fout: {0}")]
    Crypto(String),
    #[error("Opslag fout: {0}")]
    Storage(String),
    #[error("TPM fout: {0}")]
    Tpm(String),
    #[error("Audit log fout: {0}")]
    Audit(String),
    #[error("Rate limit overschreden: probeer opnieuw over {retry_after_seconds}s (resterende pogingen: {remaining_attempts})")]
    RateLimited {
        retry_after_seconds: u64,
        remaining_attempts: u32,
    },
    #[error("Validatie fout: {0}")]
    Validation(String),
    #[error("Configuratie fout: {0}")]
    Config(String),
    #[error("Niet geïnitialiseerd")]
    NotInitialized,
    #[error("Reeds geïnitialiseerd")]
    AlreadyInitialized,
    #[error("Integriteitsfout: {0}")]
    Integrity(String),
    #[error("Shamir fout: {0}")]
    Shamir(String),
    #[error("Toegang geweigerd: {0}")]
    AccessDenied(String),
    #[error("Interne fout: {0}")]
    Internal(String),
    #[error("Beveiligingsfout: {0}")]
    Security(String),
}

impl VaultError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, VaultError::RateLimited { .. })
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            VaultError::RateLimited { retry_after_seconds, .. } => {
                Some(Duration::from_secs(*retry_after_seconds))
            }
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Storage(e.to_string())
    }
}
