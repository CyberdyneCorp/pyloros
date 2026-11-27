//! URI validation and origin grouping for administrative registries.
use crate::browser_prompt::quoted_string;

pub(crate) fn validate_resource(uri: &str) -> Result<(), String> {
    let cleaned = uri.replace(['\r', '\n', '\t'], "");
    let invalid = || {
        format!(
            "resource must be an https URL without fragment: {}",
            quoted_string(uri)
        )
    };
    let cleaned = cleaned.trim_start_matches(|c: char| c <= ' ');
    let (scheme, rest) = cleaned
        .split_once("://")
        .unwrap_or(("", cleaned.strip_prefix("//").unwrap_or("")));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    validate_authority(authority, host)?;
    if !scheme.eq_ignore_ascii_case("https")
        || host.is_empty()
        || host.starts_with(':')
        || rest
            .split_once('#')
            .is_some_and(|(_, fragment)| !fragment.is_empty())
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_authority(authority: &str, host: &str) -> Result<(), String> {
    use unicode_normalization::UnicodeNormalization;
    if authority.contains(['[', ']']) {
        validate_brackets(authority, host)?;
    }
    if !authority.is_ascii() {
        let bare = authority.replace(['@', ':', '#', '?'], "");
        let normalized: String = bare.nfkc().collect();
        if normalized != bare && normalized.contains(['/', '?', '#', '@', ':']) {
            return Err(format!(
                "netloc {} contains invalid characters under NFKC normalization",
                quoted_string(authority)
            ));
        }
    }
    Ok(())
}

fn validate_brackets(authority: &str, host: &str) -> Result<(), String> {
    if !authority.contains('[') || !authority.contains(']') {
        return Err("Invalid IPv6 URL".into());
    }
    let (address, suffix) = host
        .strip_prefix('[')
        .unwrap_or(host)
        .split_once(']')
        .unwrap_or((host, ""));
    if host.find('[').is_some_and(|i| i != 0) || (!suffix.is_empty() && !suffix.starts_with(':')) {
        return Err("Invalid IPv6 URL".into());
    }
    if let Some(future) = address.strip_prefix('v') {
        return if future.split_once('.').is_some_and(|(version, tail)| {
            !version.is_empty()
                && version.bytes().all(|b| b.is_ascii_hexdigit())
                && !tail.is_empty()
        }) {
            Ok(())
        } else {
            Err("IPvFuture address is invalid".into())
        };
    }
    let not_ip = || {
        format!(
            "{} does not appear to be an IPv4 or IPv6 address",
            quoted_string(address)
        )
    };
    if address.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err("An IPv4 address cannot be in brackets".into());
    }
    let ip = match address.split_once('%') {
        Some((ip, zone)) if !zone.is_empty() && !zone.contains('%') => ip,
        Some(_) => return Err(not_ip()),
        None => address,
    };
    ip.parse::<std::net::Ipv6Addr>()
        .map(|_| ())
        .map_err(|_| not_ip())
}

pub(crate) fn redirect_origin(uri: &str) -> Option<String> {
    let cleaned = uri.replace(['\n', '\r', '\t'], "");
    let (scheme, rest) = cleaned
        .trim_start_matches(|c: char| c <= ' ')
        .split_once("://")?;
    if rest
        .split_once('#')
        .is_some_and(|(_, fragment)| !fragment.is_empty())
    {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = match authority.rsplit_once('@') {
        Some((user, host)) if user.split(':').next() == Some("") => host,
        Some(_) => return None,
        None => authority,
    };
    validate_authority(authority, host).ok()?;
    let (name, port) = if let Some(ip) = host.strip_prefix('[') {
        let (addr, suffix) = ip.split_once(']')?;
        (addr, suffix.strip_prefix(':').unwrap_or(suffix))
    } else {
        host.split_once(':').unwrap_or((host, ""))
    };
    if name.is_empty()
        || (!port.is_empty()
            && (!port.bytes().all(|c| c.is_ascii_digit()) || port.parse::<u16>().is_err()))
    {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https"
        && !(scheme == "http"
            && ["127.0.0.1", "::1", "localhost"]
                .iter()
                .any(|known| name.eq_ignore_ascii_case(known)))
    {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_lowercase()))
}

pub(crate) fn is_https_origin(value: &str) -> bool {
    let Some(origin) = redirect_origin(value) else {
        return false;
    };
    if !origin.starts_with("https://") {
        return false;
    }
    let cleaned = value.replace(['\n', '\r', '\t'], "");
    let Some((_, rest)) = cleaned.split_once("://") else {
        return false;
    };
    let tail = rest.find(['/', '?', '#']).map_or("", |i| &rest[i..]);
    matches!(tail, "" | "/" | "?" | "/?" | "#" | "/#" | "?#" | "/?#")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_configuration_accepts_bare_international_https_origins() {
        assert!(is_https_origin("https://BÜCHER.example/"));
        for value in [
            "http://bücher.example",
            "https://bücher.example/finish",
            "https://bücher.example/?name",
            "https://bücher.example/#fragment",
        ] {
            assert!(!is_https_origin(value));
        }
    }

    #[test]
    fn fragment_redirects_group_by_authority_and_preserve_explicit_ports() {
        assert_eq!(
            redirect_origin("https://Host.example:443/return?a").as_deref(),
            Some("https://host.example:443")
        );
        assert_eq!(
            redirect_origin("http://[::1]:8040/return").as_deref(),
            Some("http://[::1]:8040")
        );
        for invalid in [
            "/relative",
            "http://remote.example/end",
            "https://[::1]::443/end",
            "https://a.example/end#x",
        ] {
            assert!(redirect_origin(invalid).is_none());
        }
    }
}
