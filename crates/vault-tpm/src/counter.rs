#[cfg(feature = "tpm")]
use vault_common::{VaultError, VaultResult};

pub struct TpmCounter;

impl TpmCounter {
    pub const COUNTER_NV_INDEX: u32 = 0x01500000;
    pub const COUNTER_SIZE: u16 = 8;

    #[cfg(feature = "tpm")]
    pub fn ensure_exists(context: &mut tss_esapi::Context) -> VaultResult<()> {
        use tss_esapi::interface_types::resource_handles::{NvIndexHandle, Provision};
        use tss_esapi::structures::NvPublicBuilder;
        use tracing::info;

        let idx = NvIndexHandle::new(Self::COUNTER_NV_INDEX)
            .map_err(|e| VaultError::Tpm(format!("NV index: {}", e)))?;
        if context
            .execute_with_nullauth_session(|c| c.nv_read_public(idx))
            .is_ok()
        {
            info!("NV counter bestaat");
            return Ok(());
        }

        let nvp = NvPublicBuilder::new()
            .with_index(Self::COUNTER_NV_INDEX)
            .with_name_alg(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256)
            .with_attributes(
                tss_esapi::structures::NvAttributes::builder()
                    .with_owner_write(true)
                    .with_owner_read(true)
                    .with_nv_counter(true)
                    .with_auth_read(false)
                    .with_auth_write(false)
                    .with_nt(1)
                    .build()
                    .map_err(|e| VaultError::Tpm(format!("NV attr: {}", e)))?,
            )
            .with_data_area_size(Self::COUNTER_SIZE)
            .build()
            .map_err(|e| VaultError::Tpm(format!("NV build: {}", e)))?;

        context
            .execute_with_nullauth_session(|c| c.nv_define_space(Provision::Owner, None, nvp))
            .map_err(|e| VaultError::Tpm(format!("NV define: {}", e)))?;

        info!("NV counter aangemaakt");
        Ok(())
    }

    #[cfg(feature = "tpm")]
    pub fn read(context: &mut tss_esapi::Context) -> VaultResult<u64> {
        use tss_esapi::interface_types::resource_handles::{NvIndexHandle, Provision};

        let idx = NvIndexHandle::new(Self::COUNTER_NV_INDEX)
            .map_err(|e| VaultError::Tpm(format!("NV index: {}", e)))?;
        let bytes = context
            .execute_with_nullauth_session(|c| c.nv_read(Provision::Owner, idx))
            .map_err(|e| VaultError::Tpm(format!("NV read: {}", e)))?;
        if bytes.len() >= 8 {
            let mut d = [0u8; 8];
            d.copy_from_slice(&bytes[..8]);
            Ok(u64::from_le_bytes(d))
        } else {
            Ok(0)
        }
    }

    #[cfg(feature = "tpm")]
    pub fn increment(context: &mut tss_esapi::Context) -> VaultResult<u64> {
        use tss_esapi::interface_types::resource_handles::{NvIndexHandle, Provision};

        let idx = NvIndexHandle::new(Self::COUNTER_NV_INDEX)
            .map_err(|e| VaultError::Tpm(format!("NV index: {}", e)))?;
        context
            .execute_with_nullauth_session(|c| c.nv_increment(Provision::Owner, idx))
            .map_err(|e| VaultError::Tpm(format!("NV inc: {}", e)))?;
        Self::read(context)
    }

    #[cfg(feature = "tpm")]
    pub fn validate_against_stored(
        context: &mut tss_esapi::Context,
        stored: u64,
    ) -> VaultResult<bool> {
        let hw = Self::read(context)?;
        if stored != hw {
            tracing::warn!("NV counter mismatch! stored={} hw={}", stored, hw);
            return Ok(false);
        }
        Ok(true)
    }

    #[cfg(not(feature = "tpm"))]
    pub fn is_available() -> bool {
        false
    }
}
