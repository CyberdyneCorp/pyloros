use ipnet::IpNet;
use std::{
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reply {
    Method,
    BadRequest,
    Forbidden,
    Gateway,
}

impl Reply {
    pub(super) fn bytes(&self) -> &'static [u8] {
        match self {
            Self::Method => b"HTTP/1.1 405 Method Not Allowed\r\n\r\n",
            Self::BadRequest => b"HTTP/1.1 400 Bad Request\r\n\r\n",
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\n\r\n",
            Self::Gateway => b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
        }
    }
}

pub(super) struct Destination {
    pub host: String,
    pub port: u16,
}

impl Destination {
    pub(super) fn parse(line: &[u8], names: &[String]) -> Result<Self, Reply> {
        let mut words = std::str::from_utf8(line)
            .map_err(|_| Reply::BadRequest)?
            .split_ascii_whitespace();
        let method = words.next().unwrap_or("");
        let target = words.next().ok_or(Reply::Method)?;
        if !method.eq_ignore_ascii_case("CONNECT") {
            return Err(Reply::Method);
        }
        let (host, port) = target.rsplit_once(':').ok_or(Reply::BadRequest)?;
        let number = port.parse::<i64>().map_err(|_| Reply::BadRequest)?;
        if !matches!(number, 80 | 443) {
            return Err(Reply::Forbidden);
        }
        let lower = host.to_ascii_lowercase();
        if !names.iter().any(|n| {
            lower == *n
                || lower
                    .strip_suffix(n)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }) {
            return Err(Reply::Forbidden);
        }
        Ok(Self {
            host: host.to_owned(),
            port: number as u16,
        })
    }
}

// IPv6 hook traffic must be native global unicast. Check each DNS answer before
// choosing one, then connect to that address without resolving the name again.
static EXCLUDED: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    networks(&[
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
    ])
});
static EXCEPTIONS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    networks(&[
        "192.0.0.9/32",
        "192.0.0.10/32",
        "2001:1::1/128",
        "2001:1::2/128",
        "2001:3::/32",
        "2001:4:112::/48",
        "2001:20::/28",
        "2001:30::/28",
    ])
});
fn networks(values: &[&str]) -> Vec<IpNet> {
    values
        .iter()
        .map(|v| v.parse().expect("static network"))
        .collect()
}
fn public(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    if let IpAddr::V6(v6) = ip
        && v6.segments()[0] >> 13 != 1
    {
        return false;
    }
    !EXCLUDED.iter().any(|net| net.contains(&ip)) || EXCEPTIONS.iter().any(|net| net.contains(&ip))
}
pub(crate) fn pin(mut answers: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let first = answers.next()?;
    (public(first.ip()) && answers.all(|a| public(a.ip()))).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_rules_match_at_a_label_boundary() {
        let names = ["example.test".into()];
        for host in ["example.test", "API.example.TEST"] {
            let request = format!("CONNECT {host}:443 HTTP/1.1");
            assert!(Destination::parse(request.as_bytes(), &names).is_ok());
        }
        for host in ["notexample.test", "example.test.other"] {
            let request = format!("CONNECT {host}:443 HTTP/1.1");
            assert_eq!(
                Destination::parse(request.as_bytes(), &names).err(),
                Some(Reply::Forbidden)
            );
        }
    }

    #[test]
    fn pin_rejects_mixed_answers_and_special_use_addresses() {
        let first: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(
            pin([first, "[2606:4700:4700::1111]:443".parse().unwrap()].into_iter()),
            Some(first)
        );
        assert!(pin(std::iter::empty()).is_none());
        for raw in [
            "127.0.0.1",
            "10.1.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fec0::1",
            "fd00::1",
            "ff02::1",
            "::ffff:10.1.0.1",
            "2001:db8::1",
            "2002::1",
        ] {
            let address = SocketAddr::new(raw.parse().unwrap(), 443);
            assert!(pin([first, address].into_iter()).is_none(), "{raw}");
            assert!(pin([address, first].into_iter()).is_none(), "{raw}");
        }
    }
}
