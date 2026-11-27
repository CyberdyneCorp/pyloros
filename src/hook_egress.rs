//! An application-owned CONNECT proxy for allowlisted hook destinations.
mod policy;
pub(crate) use policy::pin;
use policy::{Destination, Reply};
use socket2::{Domain, Socket, Type};
use std::{
    collections::BTreeSet,
    env,
    error::Error,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, lookup_host},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Proxy(Option<JoinHandle<()>>);

impl Proxy {
    pub(crate) async fn configured() -> Result<Option<Arc<Self>>, Box<dyn Error>> {
        if !crate::config::flag_with_default("HOOKS_ENABLED", true)? {
            return Ok(None);
        }
        let host = env::var("HOOKS_PROXY_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = env::var("HOOKS_PROXY_PORT")
            .unwrap_or_else(|_| "8787".into())
            .parse::<u16>()?;
        let names = crate::config::string_list("HOOKS_EGRESS_ALLOWLIST")?
            .into_iter()
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        let task = match listeners(&host, port).await {
            Ok(bound) => Some(tokio::spawn(run(bound, Arc::new(names)))),
            Err(error) => {
                eprintln!("Hook egress proxy unavailable: {error}");
                None
            }
        };
        Ok(Some(Arc::new(Self(task))))
    }
    pub(crate) fn running(&self) -> bool {
        self.0.as_ref().is_some_and(|t| !t.is_finished())
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort()
        }
    }
}

async fn listeners(host: &str, port: u16) -> io::Result<Vec<TcpListener>> {
    let addresses: BTreeSet<_> = if host.is_empty() {
        [
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port),
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port),
        ]
        .into()
    } else {
        lookup_host((host, port)).await?.collect()
    };
    bind_all(addresses)
}

fn bind_all(addresses: BTreeSet<SocketAddr>) -> io::Result<Vec<TcpListener>> {
    let mut bound = Vec::new();
    for address in addresses {
        let socket = Socket::new(Domain::for_address(address), Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?
        }
        match socket.bind(&address.into()) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => continue,
            Err(e) => return Err(e),
        }
        socket.set_nonblocking(true)?;
        socket.listen(100)?;
        bound.push(TcpListener::from_std(socket.into())?);
    }
    if bound.is_empty() {
        return Err(io::ErrorKind::AddrNotAvailable.into());
    }
    Ok(bound)
}

async fn run(listeners: Vec<TcpListener>, names: Arc<Vec<String>>) {
    let mut servers = JoinSet::new();
    for listener in listeners {
        servers.spawn(serve(listener, names.clone()));
    }
    // The status covers every bound address. Stop sibling listeners if one exits.
    servers.join_next().await;
}

async fn serve(listener: TcpListener, names: Arc<Vec<String>>) {
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            _ = jobs.join_next(), if !jobs.is_empty() => {}
            result = listener.accept(), if jobs.len()<256 => {
                let Ok((socket,_))=result else {return};
                let names=Arc::clone(&names);
                jobs.spawn(async move {
                    let _ = session(socket, &names, upstream).await;
                });
            }
        }
    }
}

async fn request(reader: &mut BufReader<TcpStream>) -> io::Result<Vec<u8>> {
    let mut input = reader.take(65536);
    let mut line = Vec::new();
    input.read_until(b'\n', &mut line).await?;
    let mut header = Vec::new();
    while input.limit() > 0 {
        header.clear();
        let n = input.read_until(b'\n', &mut header).await?;
        if n == 0 || header == b"\n" || header == b"\r\n" {
            return Ok(line);
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}

async fn session<F>(
    socket: TcpStream,
    names: &[String],
    connect: impl FnOnce(Destination) -> F,
) -> io::Result<()>
where
    F: Future<Output = Result<TcpStream, Reply>>,
{
    let mut client = BufReader::new(socket);
    let line = timeout(TIMEOUT, request(&mut client)).await??;
    if line.is_empty() {
        return Ok(());
    }
    let result = match Destination::parse(&line, names) {
        Ok(dest) => connect(dest).await,
        Err(status) => Err(status),
    };
    match result {
        Ok(mut remote) => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
        }
        Err(reply) => client.write_all(reply.bytes()).await?,
    }
    Ok(())
}

async fn upstream(dest: Destination) -> Result<TcpStream, Reply> {
    let answers = timeout(TIMEOUT, lookup_host((dest.host.as_str(), dest.port)))
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(Reply::Forbidden)?;
    let address = policy::pin(answers).ok_or(Reply::Forbidden)?;
    timeout(TIMEOUT, TcpStream::connect(address))
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(Reply::Gateway)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binding_a_busy_address_releases_other_listeners() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut sockets = [first, second];
        sockets.sort_by_key(|s| s.local_addr().unwrap());
        let [first, second] = sockets;
        let free = first.local_addr().unwrap();
        let occupied = second.local_addr().unwrap();
        drop(first);
        assert_eq!(
            bind_all([free, occupied].into()).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        assert!(TcpListener::bind(free).await.is_ok());
    }

    #[tokio::test]
    async fn relays_payload_buffered_with_the_connect_request_and_returns_remote_bytes() {
        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_echo = fixture.local_addr().unwrap();
        let mut client = TcpStream::connect(ingress.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = ingress.accept().await.unwrap();
        let task = tokio::spawn(async move {
            session(socket, &["example.test".into()], |dest| async move {
                assert_eq!((dest.host.as_str(), dest.port), ("api.example.test", 443));
                TcpStream::connect(local_echo)
                    .await
                    .map_err(|_| Reply::Gateway)
            })
            .await
            .unwrap()
        });
        client
            .write_all(
                b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test\r\n\r\nhello",
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let (mut peer, _) = fixture.accept().await.unwrap();
        let mut payload = Vec::new();
        peer.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        peer.write_all(b"received").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            &response,
            b"HTTP/1.1 200 Connection Established\r\n\r\nreceived"
        );
        task.await.unwrap();
    }
}
