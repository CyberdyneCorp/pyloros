//! Ethereum wallet material created when provisioning an account.
use crate::key_encryption::{EncryptionError, KeyEncryptionKey};
use data_encoding::HEXLOWER;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

pub struct ManagedWallet {
    pub public_key: String,
    pub address: String,
    pub encrypted_private_key: Vec<u8>,
}

impl ManagedWallet {
    pub fn generate(key: &KeyEncryptionKey) -> Result<Self, EncryptionError> {
        Self::from_secret(&SecretKey::random(&mut OsRng), key)
    }

    fn from_secret(secret: &SecretKey, key: &KeyEncryptionKey) -> Result<Self, EncryptionError> {
        let point = secret.public_key().to_encoded_point(false);
        let public = point.as_bytes();
        let digest = Keccak256::digest(&public[1..]);
        let bytes = Zeroizing::new(secret.to_bytes());
        Ok(Self {
            public_key: format!("0x{}", HEXLOWER.encode(public)),
            address: checksummed(&digest[12..]),
            encrypted_private_key: key.encrypt(bytes.as_slice())?,
        })
    }
}

fn checksummed(bytes: &[u8]) -> String {
    let lower = HEXLOWER.encode(bytes);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut address = String::with_capacity(42);
    address.push_str("0x");
    for (i, c) in lower.bytes().enumerate() {
        let mask = if i % 2 == 0 { 0x80 } else { 0x08 };
        let c = if hash[i / 2] & mask != 0 {
            c.to_ascii_uppercase()
        } else {
            c
        };
        address.push(char::from(c));
    }
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_point_has_expected_address_and_recoverable_private_bytes() {
        let key = KeyEncryptionKey::new("test key for account storage").unwrap();
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        let wallet =
            ManagedWallet::from_secret(&SecretKey::from_slice(&scalar).unwrap(), &key).unwrap();
        assert_eq!(wallet.address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        assert_eq!(
            wallet.public_key,
            "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
        assert_eq!(
            key.decrypt(&wallet.encrypted_private_key)
                .unwrap()
                .as_slice(),
            scalar
        );
        let wrong = KeyEncryptionKey::new("another fixture key").unwrap();
        assert!(wrong.decrypt(&wallet.encrypted_private_key).is_err());
    }
}
