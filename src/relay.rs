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
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time;
use tracing::{debug, error, info, info_span, instrument, warn, Instrument, Span};

type ServiceDigest = protocol::Digest;
type Nonce = protocol::Digest;
type ControlChannelMap = MultiMap<ServiceDigest, Nonce, Arc<RelayControlChannelHandle>>;

const TCP_POOL_SIZE: usize = 8;
const CHAN_SIZE: usize = 2048;
const HANDSHAKE_TIMEOUT: u64 = 5;

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
    token_hash: ServiceDigest,
    service: ServerServiceConfig,
}

#[derive(Debug)]
struct RelayRegistry {
    by_digest: HashMap<ServiceDigest, RelayTunnelRuntime>,
    by_host: HashMap<String, ServiceDigest>,
}

impl RelayRegistry {
    fn from_tunnels(tunnels: &[RelayTunnelConfig]) -> Result<Self> {
        let mut by_digest = HashMap::new();
        let mut by_host = HashMap::new();

        for tunnel in tunnels {
            let host = tunnel
                .url
                .host_str()
                .ok_or_else(|| anyhow!("relay tunnel `{}` URL has no host", tunnel.id))?
                .to_ascii_lowercase();
            let digest = protocol::digest(tunnel.id.as_bytes());
            let token_hash = crate::token::parse_token_hash(&tunnel.token_hash)
                .with_context(|| format!("invalid token_hash for relay tunnel `{}`", tunnel.id))?;
            let service = ServerServiceConfig {
                service_type: ServiceType::Tcp,
                name: tunnel.id.clone(),
                bind_addr: String::new(),
                token: None,
                nodelay: tunnel.nodelay,
            };

            by_host.insert(host.clone(), digest);
            by_digest.insert(
                digest,
                RelayTunnelRuntime {
                    id: tunnel.id.clone(),
                    host,
                    token_hash,
                    service,
                },
            );
        }

        Ok(Self { by_digest, by_host })
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
        ControlChannelHello(_, service_digest) => {
            do_control_channel_handshake(
                conn,
                registry,
                control_channels,
                service_digest,
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
    service_digest: ServiceDigest,
    heartbeat_interval: u64,
) -> Result<()> {
    TcpTransport::hint(&conn, SocketOpts::for_control_channel());

    let mut nonce = [0u8; protocol::HASH_WIDTH_IN_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let hello = Hello::ControlChannelHello(protocol::CURRENT_PROTO_VERSION, nonce);
    conn.write_all(&bincode::serialize(&hello).unwrap()).await?;
    conn.flush().await?;

    let tunnel = match registry.by_digest.get(&service_digest) {
        Some(tunnel) => tunnel.clone(),
        None => {
            conn.write_all(&bincode::serialize(&Ack::ServiceNotExist).unwrap())
                .await?;
            bail!(
                "No relay tunnel for service digest {}",
                hex::encode(service_digest)
            );
        }
    };

    let Auth(response) = read_auth(&mut conn).await?;
    let session_key = crate::token::response_for_token_hash(&tunnel.token_hash, &nonce);
    if response != session_key {
        conn.write_all(&bincode::serialize(&Ack::AuthFailed).unwrap())
            .await?;
        bail!("relay tunnel `{}` failed authentication", tunnel.id);
    }

    let mut channels = control_channels.write().await;
    if channels.remove1(&service_digest).is_some() {
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
    let _ = channels.insert(service_digest, session_key, handle);
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
    let prefix = match read_http_prefix(&mut visitor, max_header_bytes).await {
        Ok(prefix) => prefix,
        Err(IngressReadError::HeaderTooLarge) => {
            write_http_error(&mut visitor, 431, "Request Header Fields Too Large").await?;
            bail!("ingress request header too large");
        }
        Err(IngressReadError::Closed) => bail!("ingress connection closed before headers"),
        Err(IngressReadError::Io(err)) => return Err(err),
    };

    let host = match extract_http_host(&prefix) {
        Some(host) => host,
        None => {
            write_http_error(&mut visitor, 400, "Bad Request").await?;
            bail!("ingress request has no Host header");
        }
    };

    let service_digest = match registry.by_host.get(host.as_ref()) {
        Some(service_digest) => *service_digest,
        None => {
            write_http_error(&mut visitor, 404, "Not Found").await?;
            bail!("unknown relay host `{host}`");
        }
    };

    let handle = {
        let channels = control_channels.read().await;
        channels.get1(&service_digest).cloned()
    };

    let handle = match handle {
        Some(handle) => handle,
        None => {
            write_http_error(&mut visitor, 503, "Service Unavailable").await?;
            bail!("relay tunnel for `{host}` is not connected");
        }
    };

    let mut data_channel = match handle.open_tcp_data_channel().await {
        Ok(data_channel) => data_channel,
        Err(err) => {
            write_http_error(&mut visitor, 502, "Bad Gateway").await?;
            return Err(err);
        }
    };

    data_channel
        .write_all(&prefix)
        .await
        .with_context(|| "failed to forward ingress prefix")?;

    let _ = copy_bidirectional(&mut data_channel, &mut visitor).await;
    Ok(())
}

enum IngressReadError {
    HeaderTooLarge,
    Closed,
    Io(anyhow::Error),
}

async fn read_http_prefix(
    visitor: &mut TcpStream,
    max_header_bytes: usize,
) -> std::result::Result<Vec<u8>, IngressReadError> {
    let mut prefix = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    let mut scan_from = 0;

    loop {
        let n = visitor
            .read(&mut buf)
            .await
            .map_err(|err| IngressReadError::Io(err.into()))?;
        if n == 0 {
            return Err(IngressReadError::Closed);
        }

        prefix.extend_from_slice(&buf[..n]);
        if find_header_end_from(&prefix, scan_from).is_some() {
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

    for raw_line in headers.split(|byte| *byte == b'\n').skip(1) {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = trim_ascii(&line[..colon]);
        if !name.eq_ignore_ascii_case(b"host") {
            continue;
        }

        let value = trim_ascii(&line[colon + 1..]);
        let host = std::str::from_utf8(value).ok()?;
        return normalize_host(host);
    }

    None
}

fn normalize_host(host: &str) -> Option<Cow<'_, str>> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }

    let host = if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else if let Some((without_port, port)) = host.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            without_port
        } else {
            host
        }
    } else {
        host
    };

    let host = host.trim_end_matches('.');
    if host.is_empty() {
        None
    } else if host.as_bytes().iter().any(|byte| byte.is_ascii_uppercase()) {
        Some(Cow::Owned(host.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(host))
    }
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
    use url::Url;

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
    fn registry_maps_exact_hosts() -> Result<()> {
        let registry = RelayRegistry::from_tunnels(&[RelayTunnelConfig {
            id: "alexander-main".into(),
            url: Url::parse("https://utuWcUQps7w0.getpioneer.dev")?,
            token_hash: crate::token::hash_token("secret").into(),
            nodelay: Some(true),
        }])?;

        let digest = protocol::digest(b"alexander-main");
        assert_eq!(
            registry.by_host.get("utuwcuqps7w0.getpioneer.dev"),
            Some(&digest)
        );
        assert!(registry.by_digest.contains_key(&digest));
        Ok(())
    }
}
