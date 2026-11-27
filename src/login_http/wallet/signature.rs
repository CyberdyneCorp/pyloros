//! Recover the signer of an Ethereum personal message.
use data_encoding::HEXLOWER_PERMISSIVE;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

pub(super) fn signer(message: &str, signature: &str) -> Option<String> {
    let hex = signature
        .strip_prefix("0x")
        .or_else(|| signature.strip_prefix("0X"))
        .unwrap_or(signature);
    let padded;
    let hex = match hex.len() {
        130 => hex,
        129 => {
            padded = format!("0{hex}");
            &padded
        }
        _ => return None,
    };
    let bytes = HEXLOWER_PERMISSIVE.decode(hex.as_bytes()).ok()?;
    let signature = Signature::from_slice(&bytes[..64]).ok()?;
    let mut parity = match bytes[64] {
        v @ 0..=1 => v,
        v @ 27..=28 => v - 27,
        v @ 35.. => (v - 35) % 2,
        _ => return None,
    };
    let signature = if let Some(low) = signature.normalize_s() {
        parity ^= 1;
        low
    } else {
        signature
    };
    let digest = Keccak256::new()
        .chain_update(format!("\x19Ethereum Signed Message:\n{}", message.len()))
        .chain_update(message.as_bytes());
    let public =
        VerifyingKey::recover_from_digest(digest, &signature, RecoveryId::from_byte(parity)?)
            .ok()?;
    Some(crate::managed_wallet::ethereum_address(
        public.to_encoded_point(false).as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_message_uses_utf8_byte_length_and_exact_newlines() {
        let message = "Wallet sign-in\nΚαλημέρα 🌍\n";
        let signature = "7abdae1d52c22e97854afbbae2f958165d2ee25018cfdf875f0f904199fcb95c405692714b812ff572bb678e555bf4ba960a19116b8d364e19c59c54348f417c1c";
        let address = "0xF1268091Da798cF0aDbE7465ce2d12c81be0E890";
        assert_eq!(signer(message, signature).as_deref(), Some(address));
        assert_eq!(
            signer(message, &format!("0X{}", signature.to_uppercase())).as_deref(),
            Some(address)
        );
        assert_ne!(
            signer(message.trim_end(), signature).as_deref(),
            Some(address)
        );
        assert_eq!(signer(message, "invalid"), None);
        assert_eq!(signer(message, &"00".repeat(65)), None);
    }
}
