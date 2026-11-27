use super::{AttestationCaList, Cbor, InvalidRegistration};
use der_parser::der::{Class, parse_der_sequence};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

// SHA-256 of each DER certificate in the Google hardware root set used by the reference service.
const HARDWARE_ROOTS: [&str; 4] = [
    "c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5",
    "1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc",
    "ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a",
    "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
];

fn tee_signing_key(description: &[u8]) -> Option<bool> {
    let (rest, description) = parse_der_sequence(description).ok()?;
    if !rest.is_empty() {
        return None;
    }
    let tee = description.as_sequence().ok()?.get(7)?.as_sequence().ok()?;
    let tagged = |tag| {
        let mut fields = tee
            .iter()
            .filter(|field| field.class() == Class::ContextSpecific && field.tag().0 == tag);
        let value = fields.next()?.as_slice().ok()?;
        fields.next().is_none().then_some(value)
    };
    // Explicit DER tags carry origin INTEGER 0 (generated) and purpose SET { INTEGER 2 } (sign).
    Some(tagged(702)? == [2, 1, 0] && tagged(1)? == [0x31, 3, 2, 1, 2])
}

pub(super) fn hardware_root(statement: &Cbor) -> Result<AttestationCaList, InvalidRegistration> {
    let Cbor::Map(fields) = statement else {
        return Err(InvalidRegistration);
    };
    let Some(Cbor::Array(chain)) = fields.get(&Cbor::Text("x5c".into())) else {
        return Err(InvalidRegistration);
    };
    let [Cbor::Bytes(leaf), .., Cbor::Bytes(root)] = chain.as_slice() else {
        return Err(InvalidRegistration);
    };
    let digest = format!("{:x}", Sha256::digest(root));
    if !HARDWARE_ROOTS.contains(&digest.as_str()) {
        return Err(InvalidRegistration);
    }
    let (rest, certificate) = X509Certificate::from_der(leaf).map_err(|_| InvalidRegistration)?;
    let extension = certificate
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == "1.3.6.1.4.1.11129.2.1.17")
        .ok_or(InvalidRegistration)?;
    if !rest.is_empty() || tee_signing_key(extension.value) != Some(true) {
        return Err(InvalidRegistration);
    }
    let pem = pem::encode(&pem::Pem::new("CERTIFICATE", root.as_slice()));
    AttestationCaList::try_from(pem.as_bytes()).map_err(|_| InvalidRegistration)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequence(fields: &[u8]) -> Vec<u8> {
        let mut sequence = vec![0x30, u8::try_from(fields.len()).unwrap()];
        sequence.extend_from_slice(fields);
        sequence
    }

    #[test]
    fn signing_purpose_and_generated_origin_belong_in_the_tee_list() {
        let sign = [0xa1, 5, 0x31, 3, 2, 1, 2];
        let sign_and_verify = [0xa1, 8, 0x31, 6, 2, 1, 2, 2, 1, 3];
        let generated = [0xbf, 0x85, 0x3e, 3, 2, 1, 0];
        let valid = [sign.as_slice(), &generated].concat();
        let accepted = |software: &[u8], tee: &[u8]| {
            let mut fields = vec![2, 1, 3, 10, 1, 1, 2, 1, 4, 10, 1, 1, 4, 0, 4, 0];
            fields.extend(sequence(software));
            fields.extend(sequence(tee));
            tee_signing_key(&sequence(&fields)) == Some(true)
        };
        assert!(accepted(&[], &valid));
        assert!(!accepted(&valid, &[]));
        assert!(!accepted(&[], &sign));
        assert!(!accepted(
            &[],
            &[sign_and_verify.as_slice(), &generated].concat()
        ));
    }
}
