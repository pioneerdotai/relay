use crate::config::{
    Config, RelayConfig, RelayTunnelConfig, ServerServiceConfig, ServiceType, TransportType,
};
use crate::config_watcher::ConfigChange;
use crate::helper::write_and_flush;
use crate::multi_map::MultiMap;
use crate::protocol::Hello::{ControlChannelHello, DataChannelHello};
use crate::protocol::{
    self, read_auth, read_control_cmd, read_hello, Ack, Auth, ControlChannelCmd, DataChannelCmd,
    Hello,
};
use crate::transport::{SocketOpts, TcpTransport, Transport};
use anyhow::{anyhow, bail, Context, Result};
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use rand::RngCore;
use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time;
use tracing::{debug, error, info, info_span, instrument, warn, Instrument, Span};

type TokenId = protocol::Digest;
type Nonce = protocol::Digest;
type ControlChannelMap = MultiMap<TokenId, Nonce, Arc<RelayControlChannelHandle>>;

const TCP_POOL_SIZE: usize = 8;
const CHAN_SIZE: usize = 2048;
const HANDSHAKE_TIMEOUT: u64 = 5;
const INGRESS_HEADER_TIMEOUT: Duration = Duration::from_secs(15);
const INGRESS_DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn run_relay(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = config.relay.ok_or_else(|| {
        anyhow!("Try to run as a relay, but the configuration is missing. Please add the `[relay]` block")
    })?;

    if config.transport.transport_type != TransportType::Tcp {
        bail!("relay supports raw tcp transport only");
    }

    let mut relay = RelayServer::from_config(config).await?;
    relay.run(shutdown_rx, update_rx).await
}

#[derive(Debug, Clone)]
struct RelayTunnelRuntime {
    id: String,
    host: String,
    token_hash: protocol::Digest,
    service: ServerServiceConfig,
}

#[derive(Debug)]
struct RelayRegistry {
    by_host: HashMap<String, TokenId>,
    by_token_id: HashMap<TokenId, RelayTunnelRuntime>,
}

impl RelayRegistry {
    fn from_tunnels(tunnels: &[RelayTunnelConfig]) -> Result<Self> {
        let mut by_host = HashMap::new();
        let mut by_token_id = HashMap::new();

        for tunnel in tunnels {
            let host = tunnel
                .url
                .host_str()
                .ok_or_else(|| anyhow!("relay tunnel `{}` URL has no host", tunnel.id))?
                .to_ascii_lowercase();
            let token_hash = crate::token::parse_token_hash(&tunnel.token_hash)
                .with_context(|| format!("invalid token_hash for relay tunnel `{}`", tunnel.id))?;
            let token_id = crate::token::routing_id_for_token_hash(&token_hash);
            if by_token_id.contains_key(&token_id) {
                bail!("duplicate relay token: each tunnel must have its own key");
            }
            let service = ServerServiceConfig {
                service_type: ServiceType::Tcp,
                name: tunnel.id.clone(),
                bind_addr: String::new(),
                token: None,
                nodelay: tunnel.nodelay,
            };

            by_host.insert(host.clone(), token_id);
            by_token_id.insert(
                token_id,
                RelayTunnelRuntime {
                    id: tunnel.id.clone(),
                    host,
                    token_hash,
                    service,
                },
            );
        }

        Ok(Self {
            by_host,
            by_token_id,
        })
    }
}

struct RelayServer {
    config: Arc<RelayConfig>,
    registry: Arc<RelayRegistry>,
    control_channels: Arc<RwLock<ControlChannelMap>>,
    transport: Arc<TcpTransport>,
}

impl RelayServer {
    async fn from_config(config: RelayConfig) -> Result<Self> {
        let registry = Arc::new(RelayRegistry::from_tunnels(&config.tunnels)?);
        let transport = Arc::new(TcpTransport::new(&config.transport)?);
        Ok(Self {
            config: Arc::new(config),
            registry,
            control_channels: Arc::new(RwLock::new(ControlChannelMap::new())),
            transport,
        })
    }

    async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        let control_listener = self
            .transport
            .bind(&self.config.control_addr)
            .await
            .with_context(|| "failed to listen at `relay.control_addr`")?;
        let ingress_listener = TcpListener::bind(&self.config.ingress_addr)
            .await
            .with_context(|| "failed to listen at `relay.ingress_addr`")?;

        info!(
            control_addr = %self.config.control_addr,
            ingress_addr = %self.config.ingress_addr,
            "relay listening"
        );

        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_millis(100),
            max_elapsed_time: None,
            ..Default::default()
        };

        loop {
            tokio::select! {
                ret = self.transport.accept(&control_listener) => {
                    match ret {
                        Ok((conn, addr)) => {
                            backoff.reset();
                            let transport = self.transport.clone();
                            let registry = self.registry.clone();
                            let control_channels = self.control_channels.clone();
                            let heartbeat_interval = self.config.heartbeat_interval;
                            tokio::spawn(async move {
                                let conn = match time::timeout(
                                    Duration::from_secs(HANDSHAKE_TIMEOUT),
                                    transport.handshake(conn),
                                ).await {
                                    Ok(Ok(conn)) => conn,
                                    Ok(Err(err)) => {
                                        error!("{err:#}");
                                        return;
                                    }
                                    Err(err) => {
                                        error!("Transport handshake timeout: {}", err);
                                        return;
                                    }
                                };

                                if let Err(err) = handle_control_connection(
                                    conn,
                                    registry,
                                    control_channels,
                                    heartbeat_interval,
                                ).await {
                                    error!("{err:#}");
                                }
                            }.instrument(info_span!("relay_control", %addr)));
                        }
                        Err(err) => {
                            if let Some(duration) = backoff.next_backoff() {
                                error!("failed to accept relay control connection: {err:#}. Retry in {duration:?}...");
                                time::sleep(duration).await;
                            }
                        }
                    }
                }
                ret = ingress_listener.accept() => {
                    match ret {
                        Ok((visitor, addr)) => {
                            let registry = self.registry.clone();
                            let control_channels = self.control_channels.clone();
                            let max_header_bytes = self.config.max_header_bytes;
                            tokio::spawn(async move {
                                if let Err(err) = handle_ingress_connection(
                                    visitor,
                                    registry,
                                    control_channels,
                                    max_header_bytes,
                                ).await {
                                    debug!(%addr, "{err:#}");
                                }
                            }.instrument(info_span!("relay_ingress", %addr)));
                        }
                        Err(err) => {
                            error!("failed to accept relay ingress connection: {err:#}");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("shutting down relay gracefully...");
                    break;
                }
                update = update_rx.recv() => {
                    if let Some(update) = update {
                        warn!("ignored relay hot update {update:?}; relay registry changes require restart");
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_control_connection(
    mut conn: TcpStream,
    registry: Arc<RelayRegistry>,
    control_channels: Arc<RwLock<ControlChannelMap>>,
    heartbeat_interval: u64,
) -> Result<()> {
    match read_hello(&mut conn).await? {
        ControlChannelHello(_, token_id) => {
            // Resolve once in O(1); never scan verifiers or fall back to a service name.
            do_control_channel_handshake(
                conn,
                registry,
                control_channels,
                token_id,
                heartbeat_interval,
            )
            .await
        }
        DataChannelHello(_, nonce) => {
            do_data_channel_handshake(conn, control_channels, nonce).await
        }
    }
}

async fn do_control_channel_handshake(
    mut conn: TcpStream,
    registry: Arc<RelayRegistry>,
    control_channels: Arc<RwLock<ControlChannelMap>>,
    token_id: TokenId,
    heartbeat_interval: u64,
) -> Result<()> {
    TcpTransport::hint(&conn, SocketOpts::for_control_channel());

    let mut nonce = [0u8; protocol::HASH_WIDTH_IN_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let hello = Hello::ControlChannelHello(protocol::CURRENT_PROTO_VERSION, nonce);
    conn.write_all(&bincode::serialize(&hello).unwrap()).await?;
    conn.flush().await?;

    // Keep the challenge/response shape for an unknown token id as well.
    let Auth(response) = read_auth(&mut conn).await?;
    let tunnel = match registry.by_token_id.get(&token_id) {
        Some(tunnel) => tunnel.clone(),
        None => {
            conn.write_all(&bincode::serialize(&Ack::AuthFailed).unwrap())
                .await?;
            conn.flush().await?;
            bail!("relay authentication failed");
        }
    };

    let session_key = crate::token::response_for_token_hash(&tunnel.token_hash, &nonce);
    if response != session_key {
        conn.write_all(&bincode::serialize(&Ack::AuthFailed).unwrap())
            .await?;
        bail!("relay tunnel `{}` failed authentication", tunnel.id);
    }

    let mut channels = control_channels.write().await;
    if channels.remove1(&token_id).is_some() {
        warn!(
            "dropping previous relay control channel for `{}`",
            tunnel.id
        );
    }
    conn.write_all(&bincode::serialize(&Ack::Ok).unwrap())
        .await?;
    conn.flush().await?;

    info!(tunnel = %tunnel.id, host = %tunnel.host, "relay control channel established");
    let handle = Arc::new(RelayControlChannelHandle::new(
        conn,
        tunnel.service,
        heartbeat_interval,
    ));
    let _ = channels.insert(token_id, session_key, handle);
    Ok(())
}

async fn do_data_channel_handshake(
    conn: TcpStream,
    control_channels: Arc<RwLock<ControlChannelMap>>,
    nonce: Nonce,
) -> Result<()> {
    let handle = {
        let channels = control_channels.read().await;
        channels.get2(&nonce).cloned()
    };

    match handle {
        Some(handle) => {
            TcpTransport::hint(&conn, SocketOpts::from_server_cfg(&handle.service));
            handle
                .data_ch_tx
                .send(conn)
                .await
                .with_context(|| "data channel for a stale relay control channel")?;
        }
        None => warn!("relay data channel has incorrect nonce"),
    }

    Ok(())
}

struct RelayControlChannelHandle {
    _shutdown_tx: broadcast::Sender<bool>,
    data_ch_tx: mpsc::Sender<TcpStream>,
    data_ch_rx: Mutex<mpsc::Receiver<TcpStream>>,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    start_forward_tcp_cmd: Vec<u8>,
    service: ServerServiceConfig,
}

impl RelayControlChannelHandle {
    #[instrument(name = "relay_handle", skip_all, fields(tunnel = %service.name))]
    fn new(conn: TcpStream, service: ServerServiceConfig, heartbeat_interval: u64) -> Self {
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<bool>(1);
        let (data_ch_tx, data_ch_rx) = mpsc::channel(CHAN_SIZE * 2);
        let (data_ch_req_tx, data_ch_req_rx) = mpsc::unbounded_channel();
        let start_forward_tcp_cmd = bincode::serialize(&DataChannelCmd::StartForwardTcp).unwrap();

        for _ in 0..TCP_POOL_SIZE {
            if let Err(err) = data_ch_req_tx.send(true) {
                error!("failed to request relay data channel: {err}");
            }
        }

        let control = RelayControlChannel {
            conn,
            shutdown_rx,
            data_ch_req_rx,
            heartbeat_interval,
        };

        tokio::spawn(
            async move {
                if let Err(err) = control.run().await {
                    error!("{err:#}");
                }
            }
            .instrument(Span::current()),
        );

        Self {
            _shutdown_tx: shutdown_tx,
            data_ch_tx,
            data_ch_rx: Mutex::new(data_ch_rx),
            data_ch_req_tx,
            start_forward_tcp_cmd,
            service,
        }
    }

    async fn open_tcp_data_channel(&self) -> Result<TcpStream> {
        self.data_ch_req_tx
            .send(true)
            .with_context(|| "relay control channel is closed")?;

        let mut data_ch_rx = self.data_ch_rx.lock().await;
        while let Some(mut conn) = data_ch_rx.recv().await {
            if write_and_flush(&mut conn, &self.start_forward_tcp_cmd)
                .await
                .is_ok()
            {
                return Ok(conn);
            }

            if self.data_ch_req_tx.send(true).is_err() {
                break;
            }
        }

        bail!(
            "no available relay data channel for `{}`",
            self.service.name
        )
    }
}

struct RelayControlChannel {
    conn: TcpStream,
    shutdown_rx: broadcast::Receiver<bool>,
    data_ch_req_rx: mpsc::UnboundedReceiver<bool>,
    heartbeat_interval: u64,
}

impl RelayControlChannel {
    async fn run(mut self) -> Result<()> {
        let create_ch_cmd = bincode::serialize(&ControlChannelCmd::CreateDataChannel).unwrap();
        let heartbeat = bincode::serialize(&ControlChannelCmd::HeartBeat).unwrap();

        loop {
            tokio::select! {
                request = self.data_ch_req_rx.recv() => {
                    if request.is_none() {
                        break;
                    }
                    write_and_flush(&mut self.conn, &create_ch_cmd)
                        .await
                        .with_context(|| "failed to request relay data channel")?;
                }
                _ = time::sleep(Duration::from_secs(self.heartbeat_interval)), if self.heartbeat_interval != 0 => {
                    write_and_flush(&mut self.conn, &heartbeat)
                        .await
                        .with_context(|| "failed to write relay heartbeat")?;
                }
                _ = self.shutdown_rx.recv() => {
                    break;
                }
            }
        }

        info!("relay control channel shutdown");
        Ok(())
    }
}

async fn handle_ingress_connection(
    mut visitor: TcpStream,
    registry: Arc<RelayRegistry>,
    control_channels: Arc<RwLock<ControlChannelMap>>,
    max_header_bytes: usize,
) -> Result<()> {
    let prefix =
        match read_http_prefix(&mut visitor, max_header_bytes, INGRESS_HEADER_TIMEOUT).await {
            Ok(prefix) => prefix,
            Err(IngressReadError::HeaderTooLarge) => {
                write_http_error(&mut visitor, 431, "Request Header Fields Too Large").await?;
                bail!("ingress request header too large");
            }
            Err(IngressReadError::Closed) => bail!("ingress connection closed before headers"),
            Err(IngressReadError::HeaderTimeout) => {
                write_http_error(&mut visitor, 408, "Request Timeout").await?;
                bail!("ingress request headers timed out");
            }
            Err(IngressReadError::Io(err)) => return Err(err),
        };

    let host = match extract_http_host(&prefix) {
        Some(host) => host,
        None => {
            write_http_error(&mut visitor, 400, "Bad Request").await?;
            bail!("ingress request has no Host header");
        }
    };

    let token_id = match registry.by_host.get(host.as_ref()) {
        Some(token_id) => *token_id,
        None => {
            write_http_error(&mut visitor, 404, "Not Found").await?;
            bail!("unknown relay host");
        }
    };

    let handle = {
        let channels = control_channels.read().await;
        channels.get1(&token_id).cloned()
    };

    let handle = match handle {
        Some(handle) => handle,
        None => {
            write_http_error(&mut visitor, 503, "Service Unavailable").await?;
            bail!("relay tunnel for `{host}` is not connected");
        }
    };

    let mut data_channel =
        match wait_for_data_channel(handle.open_tcp_data_channel(), INGRESS_DATA_CHANNEL_TIMEOUT)
            .await
        {
            Ok(data_channel) => data_channel,
            Err(IngressDataChannelError::Unavailable(err)) => {
                write_http_error(&mut visitor, 502, "Bad Gateway").await?;
                return Err(err);
            }
            Err(IngressDataChannelError::Timeout) => {
                write_http_error(&mut visitor, 504, "Gateway Timeout").await?;
                bail!("relay tunnel data channel timed out");
            }
        };

    data_channel
        .write_all(&prefix)
        .await
        .with_context(|| "failed to forward ingress prefix")?;

    match copy_bidirectional(&mut data_channel, &mut visitor).await {
        Ok(_) => debug!(
            event = "relay_tunnel_forwarding",
            outcome = "cancelled",
            reason_code = "peer_closed",
        ),
        Err(_) => debug!(
            event = "relay_tunnel_forwarding",
            outcome = "failed",
            reason_code = "io_error",
        ),
    }
    Ok(())
}

enum IngressDataChannelError {
    Timeout,
    Unavailable(anyhow::Error),
}

async fn wait_for_data_channel<F>(
    open: F,
    timeout: Duration,
) -> std::result::Result<TcpStream, IngressDataChannelError>
where
    F: Future<Output = Result<TcpStream>>,
{
    match time::timeout(timeout, open).await {
        Ok(Ok(channel)) => Ok(channel),
        Ok(Err(error)) => Err(IngressDataChannelError::Unavailable(error)),
        Err(_) => Err(IngressDataChannelError::Timeout),
    }
}

enum IngressReadError {
    HeaderTooLarge,
    HeaderTimeout,
    Closed,
    Io(anyhow::Error),
}

async fn read_http_prefix<R>(
    visitor: &mut R,
    max_header_bytes: usize,
    timeout: Duration,
) -> std::result::Result<Vec<u8>, IngressReadError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut prefix = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    let mut scan_from = 0;
    let deadline = time::Instant::now() + timeout;

    loop {
        let n = time::timeout_at(deadline, visitor.read(&mut buf))
            .await
            .map_err(|_| IngressReadError::HeaderTimeout)?
            .map_err(|err| IngressReadError::Io(err.into()))?;
        if n == 0 {
            return Err(IngressReadError::Closed);
        }

        prefix.extend_from_slice(&buf[..n]);
        if let Some(header_end) = find_header_end_from(&prefix, scan_from) {
            if header_end > max_header_bytes {
                return Err(IngressReadError::HeaderTooLarge);
            }
            return Ok(prefix);
        }
        scan_from = prefix.len().saturating_sub(3);
        if prefix.len() > max_header_bytes {
            return Err(IngressReadError::HeaderTooLarge);
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    find_header_end_from(buf, 0)
}

fn find_header_end_from(buf: &[u8], start: usize) -> Option<usize> {
    buf.get(start..)?
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| start + idx + 4)
}

fn extract_http_host(prefix: &[u8]) -> Option<Cow<'_, str>> {
    let header_end = find_header_end(prefix).unwrap_or(prefix.len());
    let headers = &prefix[..header_end];
    let mut host = None;

    for raw_line in headers.split(|byte| *byte == b'\n').skip(1) {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        if line.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
            return None;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return None;
        };
        let name = trim_ascii(&line[..colon]);
        if !name.eq_ignore_ascii_case(b"host") {
            continue;
        }
        if host.is_some() {
            return None;
        }

        let value = trim_ascii(&line[colon + 1..]);
        host = normalize_host(std::str::from_utf8(value).ok()?);
        host.as_ref()?;
    }

    host
}

fn normalize_host(host: &str) -> Option<Cow<'_, str>> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }

    let host = if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']')?;
        let address = &rest[..end];
        address.parse::<Ipv6Addr>().ok()?;
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() {
            validate_host_port(suffix.strip_prefix(':')?)?;
        }
        address
    } else if let Some((without_port, port)) = host.rsplit_once(':') {
        if without_port.contains(':') {
            // An IPv6 address in an HTTP Host field must use brackets so the
            // optional port is unambiguous.
            return None;
        }
        validate_host_port(port)?;
        without_port
    } else {
        host
    };

    let host = host.trim_end_matches('.');
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        None
    } else if host.as_bytes().iter().any(|byte| byte.is_ascii_uppercase()) {
        Some(Cow::Owned(host.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(host))
    }
}

fn validate_host_port(port: &str) -> Option<()> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().map(|_| ())
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

async fn write_http_error(stream: &mut TcpStream, status: u16, reason: &str) -> Result<()> {
    let body = format!("{status} {reason}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use url::Url;

    const PIONEER_EDGE_EXAMPLE: &str = include_str!("../examples/relay/pioneer-nginx.conf");

    fn forward_prefix_fixture(prefix: &[u8], max_header_bytes: usize) -> Result<Vec<u8>> {
        if prefix.len() > max_header_bytes || find_header_end(prefix).is_none() {
            bail!("fixture request violates ingress header bound");
        }
        extract_http_host(prefix).context("fixture request has no Host")?;
        Ok(prefix.to_vec())
    }

    fn strip_public_prefix(request: &[u8], public_prefix: &str) -> Result<Vec<u8>> {
        let request = std::str::from_utf8(request)?;
        let (request_line, tail) = request.split_once("\r\n").context("request line")?;
        let mut parts = request_line.split(' ');
        let method = parts.next().context("method")?;
        let target = parts.next().context("target")?;
        let version = parts.next().context("version")?;
        if parts.next().is_some() {
            bail!("invalid fixture request line");
        }
        let upstream_target = target
            .strip_prefix(public_prefix)
            .context("target is outside configured public prefix")?;
        let upstream_target = format!("/{}", upstream_target.trim_start_matches('/'));
        Ok(format!("{method} {upstream_target} {version}\r\n{tail}").into_bytes())
    }

    #[test]
    fn extracts_and_normalizes_host() {
        let request =
            b"GET / HTTP/1.1\r\nHost: UtuWcUQps7w0.GetPioneer.Dev:443\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(
            extract_http_host(request).as_deref(),
            Some("utuwcuqps7w0.getpioneer.dev")
        );
    }

    #[test]
    fn duplicate_or_malformed_host_headers_are_rejected() {
        for request in [
            b"GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: gateway.example\r\n malformed-fold\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: gateway.example/escape\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: gateway.example:\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: gateway.example:99999\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: [::1]garbage\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: [::1]:\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: ::1\r\n\r\n".as_slice(),
        ] {
            assert!(extract_http_host(request).is_none());
        }
    }

    #[test]
    fn bracketed_ipv6_host_with_port_is_normalized() {
        assert_eq!(
            extract_http_host(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n").as_deref(),
            Some("2001:db8::1")
        );
    }

    #[tokio::test]
    async fn header_bound_applies_to_header_end_not_read_chunk_size() {
        let (mut visitor, mut peer) = tokio::io::duplex(4096);
        let oversized = format!(
            "GET / HTTP/1.1\r\nHost: gateway.example\r\nX-Fill: {}\r\n\r\n",
            "a".repeat(1100)
        );
        peer.write_all(oversized.as_bytes()).await.unwrap();
        assert!(matches!(
            read_http_prefix(&mut visitor, 1024, Duration::from_secs(1)).await,
            Err(IngressReadError::HeaderTooLarge)
        ));

        let (mut visitor, mut peer) = tokio::io::duplex(4096);
        let mut header_and_body = b"GET / HTTP/1.1\r\nHost: gateway.example\r\n\r\n".to_vec();
        header_and_body.extend(vec![b'x'; 2048]);
        peer.write_all(&header_and_body).await.unwrap();
        let prefix = match read_http_prefix(&mut visitor, 1024, Duration::from_secs(1)).await {
            Ok(prefix) => prefix,
            Err(_) => panic!("bounded fixture header must be accepted"),
        };
        assert!(prefix.starts_with(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn registry_maps_exact_hosts() -> Result<()> {
        let registry = RelayRegistry::from_tunnels(&[RelayTunnelConfig {
            id: "alexander-main".into(),
            url: Url::parse("https://utuWcUQps7w0.getpioneer.dev")?,
            token_hash: crate::token::hash_token("secret").into(),
            nodelay: Some(true),
        }])?;

        let digest = crate::token::routing_id_for_token("secret");
        assert_eq!(
            registry.by_host.get("utuwcuqps7w0.getpioneer.dev"),
            Some(&digest)
        );
        assert!(registry.by_token_id.contains_key(&digest));
        Ok(())
    }

    #[test]
    fn raw_tunnel_preserves_root_wss_and_storage_request_metadata_byte_for_byte() -> Result<()> {
        let cases: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: gateway.example.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nAuthorization: Bearer test-token\r\nPioneer-Protocol-Version: 1\r\n\r\n",
            b"GET /storage/workspaces/W1/artifacts/A1/versions/V1/content HTTP/1.1\r\nHost: gateway.example.invalid\r\nAuthorization: Bearer test-token\r\nPioneer-Protocol-Version: 1\r\nRange: bytes=0-1023\r\nIf-Range: \"sha256-test\"\r\n\r\n",
            b"HEAD /storage/workspaces/W1/artifacts/A1/versions/V1/content HTTP/1.1\r\nHost: gateway.example.invalid\r\nAuthorization: Bearer test-token\r\nPioneer-Protocol-Version: 1\r\nIf-None-Match: \"sha256-test\"\r\n\r\n",
            b"GET /storage/views/opaque-test-grant HTTP/1.1\r\nHost: gateway.example.invalid\r\n\r\n",
            b"GET /storage/members/P1/avatar/revision-1 HTTP/1.1\r\nHost: gateway.example.invalid\r\nAuthorization: Bearer test-token\r\nPioneer-Protocol-Version: 1\r\nIf-None-Match: \"avatar-revision-1\"\r\n\r\n",
        ];

        for request in cases {
            assert_eq!(forward_prefix_fixture(request, 8 * 1024)?, *request);
        }
        Ok(())
    }

    #[test]
    fn custom_public_prefix_maps_root_and_storage_to_one_upstream_tunnel() -> Result<()> {
        let wss = b"GET /pioneer/ HTTP/1.1\r\nHost: gateway.example.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let storage = b"GET /pioneer/storage/members/P1/avatar/R1 HTTP/1.1\r\nHost: gateway.example.invalid\r\n\r\n";
        let webhook =
            b"GET /pioneer/webhooks/future HTTP/1.1\r\nHost: gateway.example.invalid\r\n\r\n";

        assert!(strip_public_prefix(wss, "/pioneer/")?.starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(strip_public_prefix(storage, "/pioneer/")?
            .starts_with(b"GET /storage/members/P1/avatar/R1 HTTP/1.1\r\n"));
        // Relay does not create a webhook handler; the transformed request is
        // still handled by Gateway's explicitly unregistered namespace (404).
        assert!(strip_public_prefix(webhook, "/pioneer/")?
            .starts_with(b"GET /webhooks/future HTTP/1.1\r\n"));
        Ok(())
    }

    #[test]
    fn edge_example_has_closed_streaming_tls_header_and_logging_policy() {
        for required in [
            "return 308 https://gateway.example.invalid$request_uri",
            "proxy_http_version 1.1",
            "proxy_set_header Host $host",
            "proxy_set_header Upgrade $http_upgrade",
            "proxy_set_header Connection $pioneer_connection_upgrade",
            "proxy_set_header Authorization $http_authorization",
            "proxy_set_header Pioneer-Protocol-Version $http_pioneer_protocol_version",
            "proxy_set_header Range $http_range",
            "proxy_set_header If-Range $http_if_range",
            "proxy_set_header If-None-Match $http_if_none_match",
            "proxy_set_header Cookie \"\"",
            "proxy_set_header X-Forwarded-For $remote_addr",
            "proxy_buffering off",
            "proxy_request_buffering off",
            "proxy_read_timeout 3600s",
            "proxy_connect_timeout 15s",
            "client_header_buffer_size 8k",
            "client_max_body_size 1k",
            "/pioneer/storage/views/[REDACTED]",
        ] {
            assert!(
                PIONEER_EDGE_EXAMPLE.contains(required),
                "missing {required}"
            );
        }
        assert!(!PIONEER_EDGE_EXAMPLE.contains("Access-Control-Allow-Origin *"));
        assert!(!PIONEER_EDGE_EXAMPLE
            .contains("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for"));
        assert!(!PIONEER_EDGE_EXAMPLE.contains("return 308 https://$host"));
    }

    #[tokio::test]
    async fn bounded_duplex_fixture_streams_chunks_and_propagates_disconnect() -> Result<()> {
        let (mut visitor_peer, mut relay_visitor) = tokio::io::duplex(32);
        let (mut tunnel_peer, mut relay_tunnel) = tokio::io::duplex(32);
        let forwarding =
            tokio::spawn(
                async move { copy_bidirectional(&mut relay_tunnel, &mut relay_visitor).await },
            );

        let request =
            b"GET /storage/views/redacted HTTP/1.1\r\nHost: gateway.example.invalid\r\n\r\n";
        let request_writer = tokio::spawn(async move {
            visitor_peer.write_all(request).await?;
            visitor_peer.shutdown().await?;
            let mut response = Vec::new();
            visitor_peer.read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        });

        let mut received = vec![0_u8; request.len()];
        tunnel_peer.read_exact(&mut received).await?;
        assert_eq!(received, request);
        for chunk in [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: sandbox; default-src 'none'\r\n\r\n".as_slice(),
            b"4\r\ntest\r\n".as_slice(),
            b"0\r\n\r\n".as_slice(),
        ] {
            tunnel_peer.write_all(chunk).await?;
        }
        tunnel_peer.shutdown().await?;

        let response = request_writer.await??;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response
            .windows(b"X-Content-Type-Options: nosniff".len())
            .any(|window| window == b"X-Content-Type-Options: nosniff"));
        assert!(!response
            .windows(b"Access-Control-Allow-Origin".len())
            .any(|window| window == b"Access-Control-Allow-Origin"));
        assert!(response.ends_with(b"0\r\n\r\n"));
        forwarding.await??;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn ingress_header_deadline_is_absolute_across_partial_reads() -> Result<()> {
        let (mut visitor, mut peer) = tokio::io::duplex(128);
        peer.write_all(b"GET /").await?;
        let reader = tokio::spawn(async move {
            read_http_prefix(&mut visitor, 8 * 1024, Duration::from_secs(5)).await
        });

        tokio::task::yield_now().await;
        time::advance(Duration::from_secs(5)).await;
        assert!(matches!(
            reader.await.unwrap(),
            Err(IngressReadError::HeaderTimeout)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn ingress_data_channel_wait_has_an_absolute_deadline() {
        let waiting = tokio::spawn(async {
            wait_for_data_channel(
                std::future::pending::<Result<TcpStream>>(),
                Duration::from_secs(5),
            )
            .await
        });

        tokio::task::yield_now().await;
        time::advance(Duration::from_secs(5)).await;
        assert!(matches!(
            waiting.await.unwrap(),
            Err(IngressDataChannelError::Timeout)
        ));
    }
}
