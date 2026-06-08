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

    pub fn user_message(&self) -> &str {
        match self {
            VaultError::Crypto(_) => "Er is een versleutelingsfout opgetreden. Herstart de service en probeer opnieuw.",
            VaultError::Storage(_) => "Kan niet lezen/schrijven naar opslag. Controleer schijfruimte en bestandsrechten.",
            VaultError::Tpm(_) => "TPM communicatie mislukt. Controleer of de TPM chip actief is in BIOS/UEFI.",
            VaultError::Audit(_) => "Audit logging mislukt. Controleer schrijfrechten op de data directory.",
            VaultError::RateLimited { .. } => {
                "Te veel mislukte pogingen. Wacht even en probeer opnieuw."
            }
            VaultError::Validation(_) => "Ongeldige invoer. Controleer de opgegeven waarden.",
            VaultError::Config(_) => "Configuratie is ongeldig. Controleer de instellingen of voer de setup wizard opnieuw uit.",
            VaultError::NotInitialized => "De vault is nog niet geïnitialiseerd. Voer eerst de setup wizard uit.",
            VaultError::AlreadyInitialized => "De vault is al geconfigureerd. Gebruik 'reset' als je opnieuw wilt beginnen.",
            VaultError::Integrity(_) => "Integriteitscontrole mislukt! Mogelijke manipulatie gedetecteerd. Herstel vanuit een backup.",
            VaultError::Shamir(_) => "Shamir key-reconstructie mislukt. Zorg dat je voldoende geldige shares hebt.",
            VaultError::AccessDenied(_) => "Toegang geweigerd. Controleer of je de juiste rechten hebt.",
            VaultError::Internal(_) => "Interne fout. Herstart de service. Neem contact op met ondersteuning als dit aanhoudt.",
            VaultError::Security(_) => "Beveiligingsschending gedetecteerd. De vault is vergrendeld als voorzorgsmaatregel.",
        }
    }

    pub fn recovery_hint(&self) -> &str {
        match self {
            VaultError::Crypto(_) => "Actie: Herstart SovereignKernelVault service via Services.msc of 'sc.exe start SovereignKernelVault'",
            VaultError::Storage(_) => "Actie: Controleer C:\\ProgramData\\SovereignKernel\\Data rechten en beschikbare schijfruimte",
            VaultError::Tpm(_) => "Actie: Open Apparaatbeheer > Beveiligingsapparaten. Controleer TPM status via tpm.msc",
            VaultError::Audit(_) => "Actie: Controleer schrijfrechten: icacls C:\\ProgramData\\SovereignKernel\\Data",
            VaultError::RateLimited { .. } => "Actie: Wacht de aangegeven tijd en probeer opnieuw. Bij nood: herstart de service",
            VaultError::Validation(_) => "Actie: Controleer invoer op speciale tekens en lengte-eisen",
            VaultError::Config(_) => "Actie: Verwijder config en voer setup wizard opnieuw uit, of bewerk handmatig",
            VaultError::NotInitialized => "Actie: Start de desktop UI of voer 'vault-db-tool init' uit",
            VaultError::AlreadyInitialized => "Actie: Gebruik 'vault-db-tool reset --confirm' om opnieuw te beginnen (WAARSCHUWING: data gaat verloren)",
            VaultError::Integrity(_) => "Actie: Gebruik 'vault-db-tool restore --latest' om de laatste backup te herstellen",
            VaultError::Shamir(_) => "Actie: Verzamel minimaal 3 van de 5 shares en probeer opnieuw",
            VaultError::AccessDenied(_) => "Actie: Voer de applicatie uit als Administrator of controleer service-account rechten",
            VaultError::Internal(_) => "Actie: Check logs in C:\\ProgramData\\SovereignKernel\\Logs en herstart de service",
            VaultError::Security(_) => "Actie: Controleer Event Viewer (Windows Logboeken) voor details over de beveiligingsgebeurtenis",
        }
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Storage(e.to_string())
    }
}
