//! Authenticated storage for account secrets shared by both deployments.
use ring::{
    aead, hkdf,
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroizing;

pub struct KeyEncryptionKey(aead::LessSafeKey);

#[derive(Debug, thiserror::Error)]
#[error("account secret encryption failed")]
pub struct EncryptionError;

impl KeyEncryptionKey {
    pub fn new(master: &str) -> Result<Self, EncryptionError> {
        if master.is_empty() {
            return Err(EncryptionError);
        }
        let source = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(master.as_bytes());
        let key = source
            .expand(
                &[b"cyberdyne-auth:key-encryption-key:v1"],
                &aead::AES_256_GCM,
            )
            .map_err(|_| EncryptionError)?;
        Ok(Self(aead::LessSafeKey::new(key.into())))
    }

    pub(crate) fn encrypt(&self, secret: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.encrypt_with_aad(secret, &[])
    }

    pub(crate) fn encrypt_with_aad(
        &self,
        secret: &[u8],
        associated: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| EncryptionError)?;
        let mut buffer = Zeroizing::new(secret.to_vec());
        let tag = self
            .0
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(associated),
                &mut buffer,
            )
            .map_err(|_| EncryptionError)?;
        let mut envelope = Vec::with_capacity(nonce.len() + buffer.len() + tag.as_ref().len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&buffer);
        envelope.extend_from_slice(tag.as_ref());
        Ok(envelope)
    }

    pub(crate) fn decrypt(&self, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
        let (nonce, data) = envelope.split_at_checked(12).ok_or(EncryptionError)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| EncryptionError)?;
        let mut buffer = Zeroizing::new(data.to_vec());
        let size = self
            .0
            .open_in_place(nonce, aead::Aad::empty(), &mut buffer)
            .map_err(|_| EncryptionError)?
            .len();
        buffer.truncate(size);
        Ok(buffer)
    }
}
