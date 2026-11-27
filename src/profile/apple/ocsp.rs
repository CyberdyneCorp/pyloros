use super::verifier::Fault;
use openssl::{
    hash::MessageDigest,
    ocsp::{
        OcspBasicResponseRef, OcspCertId, OcspCertStatus, OcspFlag, OcspRequest, OcspResponse,
        OcspResponseStatus,
    },
    stack::Stack,
    x509::{X509, store::X509Store},
};

pub(super) async fn check(
    http: &reqwest::Client,
    roots: &X509Store,
    cert: &X509,
    issuer: &X509,
) -> Result<(), Fault> {
    let id = || OcspCertId::from_cert(MessageDigest::sha256(), cert, issuer);
    let mut request = OcspRequest::new()?;
    request.add_id(id()?)?;
    let body = request.to_der()?;
    let mut issuers = Stack::new()?;
    issuers.push(issuer.clone())?;
    let locations: Vec<String> = cert
        .ocsp_responders()?
        .iter()
        .map(|s| s.to_string())
        .collect();
    for location in locations {
        let url = url::Url::parse(&location).map_err(|_| Fault::Invalid)?;
        if !matches!(url.scheme(), "http" | "https") {
            continue;
        }
        let Ok(response) = http
            .post(url)
            .header("content-type", "application/ocsp-request")
            .body(body.clone())
            .send()
            .await
        else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let bytes = response.bytes().await.map_err(|_| Fault::Unavailable)?;
        let response = OcspResponse::from_der(&bytes)?;
        if response.status() != OcspResponseStatus::SUCCESSFUL {
            continue;
        }
        let basic = response.basic()?;
        basic.verify(&issuers, roots, OcspFlag::empty())?;
        return verified_status(&basic, cert, issuer);
    }
    Err(Fault::Unavailable)
}

// A responder may identify the certificate with a different digest from the request.
fn verified_status(
    response: &OcspBasicResponseRef,
    cert: &X509,
    issuer: &X509,
) -> Result<(), Fault> {
    for digest in [
        MessageDigest::sha256(),
        MessageDigest::sha1(),
        MessageDigest::sha384(),
        MessageDigest::sha512(),
    ] {
        let id = OcspCertId::from_cert(digest, cert, issuer)?;
        let Some(status) = response.find_status(&id) else {
            continue;
        };
        if status.status != OcspCertStatus::GOOD || status.next_update().is_none() {
            return Err(Fault::Invalid);
        }
        status.check_validity(60, None)?;
        return Ok(());
    }
    Err(Fault::Invalid)
}
