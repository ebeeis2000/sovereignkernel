use vault_common::VaultResult;

#[cfg(feature = "tpm")]
use tss_esapi::{
    interface_types::algorithm::{HashingAlgorithm, SymmetricDefinitionObject as Cipher},
    interface_types::session_handles::SessionHandle,
    structures::SessionType,
    Context,
};

#[cfg(feature = "tpm")]
pub struct TpmSessionGuard<'a> {
    context: &'a mut Context,
    handle: SessionHandle,
    active: bool,
}

#[cfg(feature = "tpm")]
impl<'a> TpmSessionGuard<'a> {
    pub fn new_encrypted(c: &'a mut Context) -> VaultResult<Self> {
        let s = c
            .start_auth_session(None, None, None, SessionType::Hmac, Cipher::aes_128_cfb(), HashingAlgorithm::Sha256)
            .map_err(|e| vault_common::VaultError::Tpm(format!("Session start: {}", e)))?;
        let handle: SessionHandle = s
            .try_into()
            .map_err(|e| vault_common::VaultError::Tpm(format!("Session handle: {:?}", e)))?;
        Ok(Self { context: c, handle, active: true })
    }

    pub fn handle(&self) -> SessionHandle {
        self.handle
    }

    pub fn mark_cleaned(&mut self) {
        self.active = false;
    }
}

#[cfg(feature = "tpm")]
impl<'a> Drop for TpmSessionGuard<'a> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.context.flush_context(self.handle.into());
        }
    }
}
