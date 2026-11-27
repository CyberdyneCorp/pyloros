use bip32::{ChildNumber, DerivationPath, PrivateKey, XPrv};
use bip39::{Language, Mnemonic};
use data_encoding::HEXLOWER;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub(super) fn derive(phrase: &str, index: i128) -> Option<Zeroizing<String>> {
    let normalized = Zeroizing::new(phrase.nfkd().collect::<String>());
    let words: Vec<_> = normalized.split(' ').collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return None;
    }
    let languages: Vec<_> = Language::ALL
        .iter()
        .copied()
        .filter(|lang| words.iter().all(|w| lang.find_word(w).is_some()))
        .collect();
    let language = match languages.as_slice() {
        [language] => *language,
        [Language::SimplifiedChinese, Language::TraditionalChinese] => Language::SimplifiedChinese,
        _ => return None,
    };
    let mnemonic = Mnemonic::parse_in_normalized(language, &normalized).ok()?;
    let index = u32::try_from(index).ok()?;
    let path: DerivationPath = "m/44'/60'/0'/0".parse().ok()?;
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let parent = XPrv::derive_from_path(seed.as_slice(), &path).ok()?;
    let key = Zeroizing::new(child_key(&parent, index)?);
    Some(Zeroizing::new(HEXLOWER.encode(key.as_slice())))
}

fn child_key(parent: &XPrv, index: u32) -> Option<[u8; 32]> {
    const LIMIT: u32 = 1 << 31;
    if index != LIMIT {
        return Some(
            parent
                .derive_child(ChildNumber::new(index, false).ok()?)
                .ok()?
                .to_bytes(),
        );
    }
    // Existing callers can select 2^31 as the final, non-hardened account index.
    let mac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &parent.attrs().chain_code);
    let mut mac = ring::hmac::Context::with_key(&mac_key);
    mac.update(&parent.public_key().to_bytes());
    mac.update(&index.to_be_bytes());
    let tweak = mac.sign();
    let child = parent
        .private_key()
        .derive_child(tweak.as_ref()[..32].try_into().ok()?)
        .ok()?;
    Some(child.to_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_settings::{ChainSettings, Update};

    #[tokio::test]
    async fn derives_distinct_signers_and_checks_the_account_index_boundary() {
        let words = format!("{}about", "abandon ".repeat(11));
        for (index, expected) in [
            (0, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
            (1, "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"),
            (1 << 31, "0xED33687282329c18908567c6Ae320BD2Bc0d314a"),
        ] {
            let key = derive(&words, index).unwrap();
            let view = ChainSettings::default()
                .update(Update {
                    private_key: Some(key),
                    ..Default::default()
                })
                .await;
            assert_eq!(view.signer_address.as_deref(), Some(expected));
        }
        assert!(derive(&words, (1 << 31) + 1).is_none());
        assert!(derive("invalid mnemonic", 0).is_none());
    }
}
