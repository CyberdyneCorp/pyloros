//! Preserve each peer's connection error on the final health retry.
use super::{CLIENT, Chain, ReadError, RpcRead};
use hyper_util::client::proxy::matcher::Matcher;
use reqwest::{Client, Url};
use serde_json::Value;
use std::{collections::HashSet, net::SocketAddr};

impl Chain {
    pub(super) async fn retry_health_by_address(&self, body: &str) -> Result<Value, ReadError> {
        tokio::time::timeout(self.timeout, self.health_by_address(body))
            .await
            .unwrap_or_else(|_| Err(ReadError::Transport(Some(String::new()))))
    }

    async fn health_by_address(&self, body: &str) -> Result<Value, ReadError> {
        let url = Url::parse(&self.endpoint).map_err(|_| ReadError::Failure)?;
        let host = url.domain().ok_or(ReadError::Failure)?;
        let port = url.port_or_known_default().ok_or(ReadError::Failure)?;
        // Keep the ordinary transport for endpoints routed through a proxy.
        let uri = url.as_str().parse().map_err(|_| ReadError::Failure)?;
        if Matcher::from_system().intercept(&uri).is_some() {
            return self.request(&CLIENT, body, RpcRead::Health).await;
        }
        let addresses = resolve(host, port)
            .await
            .map_err(|_| ReadError::Transport(None))?;
        let mut seen = HashSet::new();
        let mut failures = Vec::new();
        for address in addresses
            .into_iter()
            .filter(|address| seen.insert(*address))
        {
            let client = Client::builder()
                .no_gzip()
                .no_deflate()
                .resolve(host, address)
                .build()
                .map_err(|_| ReadError::Failure)?;
            match self.request(&client, body, RpcRead::Health).await {
                Err(ReadError::HostRefused(errno)) => failures.push((address, errno)),
                response => return response,
            }
        }
        Err(ReadError::Transport(refusals(host, port, &failures)))
    }
}

#[cfg(unix)]
async fn resolve(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    let host = host.to_owned();
    tokio::task::spawn_blocking(move || {
        let hints = dns_lookup::AddrInfoHints {
            flags: libc::AI_ADDRCONFIG,
            socktype: libc::SOCK_STREAM,
            ..Default::default()
        };
        dns_lookup::getaddrinfo(Some(&host), Some(&port.to_string()), Some(hints))?
            .map(|entry| entry.map(|info| info.sockaddr))
            .collect()
    })
    .await?
}

#[cfg(not(unix))]
async fn resolve(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host((host, port)).await?.collect())
}

fn peer(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(v) => format!("('{}', {})", v.ip(), v.port()),
        SocketAddr::V6(v) => format!(
            "('{}', {}, {}, {})",
            v.ip(),
            v.port(),
            v.flowinfo(),
            v.scope_id()
        ),
    }
}

fn refusals(host: &str, port: u16, failures: &[(SocketAddr, i32)]) -> Option<String> {
    let detail = match failures {
        [] => return None,
        [(addr, _)] => format!("Connect call failed {}", peer(*addr)),
        multiple => {
            let errors = multiple
                .iter()
                .map(|(addr, errno)| format!("[Errno {errno}] Connect call failed {}", peer(*addr)))
                .collect::<Vec<_>>();
            format!("Multiple exceptions: {}", errors.join(", "))
        }
    };
    Some(format!(
        "Cannot connect to host {host}:{port} ssl:default [{detail}]"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refused_hostname_reports_socket_failures_through_health_read() {
        // Close the listener before the provider attempts to connect.
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let chain = Chain::for_health_test(format!("http://localhost:{port}"));
        let error = chain.health_block().await.unwrap_err();
        assert!(
            error.starts_with(&format!(
                "Cannot connect to host localhost:{port} ssl:default ["
            )),
            "{error}"
        );
        assert!(
            error.contains(&format!("Connect call failed ('127.0.0.1', {port})")),
            "{error}"
        );
    }

    #[test]
    fn dual_stack_refusals_retain_peer_order_and_native_errors() {
        let failed = [
            ("[::1]:1234".parse().unwrap(), 61),
            ("127.0.0.1:1234".parse().unwrap(), 61),
        ];
        assert_eq!(
            refusals("localhost", 1234, &failed).unwrap(),
            "Cannot connect to host localhost:1234 ssl:default [Multiple exceptions: [Errno 61] Connect call failed ('::1', 1234, 0, 0), [Errno 61] Connect call failed ('127.0.0.1', 1234)]"
        );
    }
}
