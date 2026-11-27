//! Verify a StoreKit signature before trusting any claims or certificate URLs.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    nid::Nid,
    sha::sha256,
    stack::Stack,
    x509::{
        X509, X509StoreContext,
        store::{X509Store, X509StoreBuilder},
        verify::X509VerifyFlags,
    },
};
use serde::{Deserialize, de::DeserializeOwned};
use std::{path::Path, time::Duration};
use x509_parser::prelude::FromDer;

#[derive(Debug, thiserror::Error)]
pub(super) enum Fault {
    #[error("invalid signed data")]
    Invalid,
    #[error("certificate status unavailable")]
    Unavailable,
}
impl From<openssl::error::ErrorStack> for Fault {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Self::Invalid
    }
}
pub(super) struct Verifier {
    roots: X509Store,
    http: reqwest::Client,
}
#[derive(Deserialize)]
struct Header {
    alg: String,
    x5c: [String; 3],
}

impl Verifier {
    pub(super) fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut store = X509StoreBuilder::new()?;
        store.set_flags(X509VerifyFlags::X509_STRICT)?;
        let mut count = 0;
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if path.is_file() && matches!(ext.as_str(), "cer" | "der" | "crt") {
                store.add_cert(X509::from_der(&std::fs::read(path)?)?)?;
                count += 1;
            }
        }
        if count == 0 {
            return Err("no App Store trust roots configured".into());
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            roots: store.build(),
            http,
        })
    }

    pub(super) async fn decode<T: DeserializeOwned>(&self, signed: &str) -> Result<T, Fault> {
        let (input, signature) = signed.rsplit_once('.').ok_or(Fault::Invalid)?;
        let (header, payload) = input.split_once('.').ok_or(Fault::Invalid)?;
        let header: Header =
            serde_json::from_slice(&decode(header)?).map_err(|_| Fault::Invalid)?;
        if header.alg != "ES256" {
            return Err(Fault::Invalid);
        }
        let [leaf, issuer, root] = self.chain(header.x5c)?;
        let key = leaf.public_key()?.ec_key()?;
        let sig = decode(signature)?;
        if key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) || sig.len() != 64 {
            return Err(Fault::Invalid);
        }
        let (r, s) = sig.split_at(32);
        let signature =
            EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
        if !signature.verify(&sha256(input.as_bytes()), &key)? {
            return Err(Fault::Invalid);
        }
        let claims = serde_json::from_slice(&decode(payload)?).map_err(|_| Fault::Invalid)?;
        tokio::try_join!(
            super::ocsp::check(&self.http, &self.roots, &leaf, &issuer),
            super::ocsp::check(&self.http, &self.roots, &issuer, &root)
        )?;
        Ok(claims)
    }
    fn chain(&self, certificates: [String; 3]) -> Result<[X509; 3], Fault> {
        let [leaf, issuer, root] = certificates;
        let leaf = cert(&leaf, Some("1.2.840.113635.100.6.11.1"))?;
        let issuer = cert(&issuer, Some("1.2.840.113635.100.6.2.1"))?;
        let root = cert(&root, None)?;
        let mut untrusted = Stack::new()?;
        untrusted.push(issuer.clone())?;
        let mut ctx = X509StoreContext::new()?;
        let verified = ctx.init(&self.roots, &leaf, &untrusted, |ctx| {
            Ok(ctx.verify_cert()?
                && ctx
                    .chain()
                    .is_some_and(|c| c.len() == 3 && c[1] == *issuer && c[2] == *root))
        })?;
        if !verified {
            return Err(Fault::Invalid);
        }
        Ok([leaf, issuer, root])
    }
}
fn cert(encoded: &str, purpose: Option<&str>) -> Result<X509, Fault> {
    let der = STANDARD.decode(encoded).map_err(|_| Fault::Invalid)?;
    let (rest, parsed) =
        x509_parser::certificate::X509Certificate::from_der(&der).map_err(|_| Fault::Invalid)?;
    if !rest.is_empty()
        || purpose.is_some_and(|oid| {
            !parsed
                .extensions()
                .iter()
                .any(|e| e.oid.to_id_string() == oid)
        })
    {
        return Err(Fault::Invalid);
    }
    Ok(X509::from_der(&der)?)
}
fn decode(s: &str) -> Result<Vec<u8>, Fault> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| Fault::Invalid)
}

#[cfg(test)]
#[path = "verifier_tests.rs"]
mod tests;
