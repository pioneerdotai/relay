//! An authenticated media stream belongs to one authorized signaling socket.
//! Public UDP tuples are assigned only after the corresponding SFU answers ICE.
use super::{find_header_end, trim_ascii, TokenId};
use anyhow::{ensure, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::{self, Instant};

const PATH: &[u8] = b"/_pioneer/call-media/v1";
const REGISTER: u8 = 1;
const DATAGRAM: u8 = 2;
const ACK: u8 = 3;
const KEEPALIVE: u8 = 4;
const MAX_PACKET: usize = 4096;
const MAX_FRAME: usize = 8192;
const MAX_SESSIONS: usize = 1024;
const MAX_SESSIONS_PER_TUNNEL: usize = 128;
const MAX_ROUTES: usize = 16;
const MAX_FLOWS: usize = 16;
const MAX_TRANSACTIONS: usize = 8;
const PENDING_TTL: Duration = Duration::from_secs(10);
const CONSENT_TTL: Duration = Duration::from_secs(90);
const FRAME_TIMEOUT: Duration = Duration::from_secs(40);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn is_media_request(prefix: &[u8]) -> bool {
    prefix.split(|b| *b == b' ').nth(1) == Some(PATH)
}

pub(super) fn validate_upgrade(prefix: &[u8]) -> bool {
    if !prefix.starts_with(b"GET /_pioneer/call-media/v1 HTTP/1.1\r\n")
        || find_header_end(prefix) != Some(prefix.len())
    {
        return false;
    }

    let mut upgrade = false;
    let mut connection = false;
    for line in prefix.split(|b| *b == b'\n').skip(1) {
        let line = trim_ascii(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            break;
        };
        let (name, value) = (&line[..colon], trim_ascii(&line[colon + 1..]));
        if name.eq_ignore_ascii_case(b"upgrade") {
            if upgrade || !value.eq_ignore_ascii_case(b"pioneer-call-media-v1") {
                return false;
            }
            upgrade = true;
        }
        if name.eq_ignore_ascii_case(b"connection") {
            connection |= value
                .split(|b| *b == b',')
                .any(|value| trim_ascii(value).eq_ignore_ascii_case(b"upgrade"));
        }
        if name.eq_ignore_ascii_case(b"transfer-encoding")
            || (name.eq_ignore_ascii_case(b"content-length") && value != b"0")
        {
            return false;
        }
    }
    upgrade && connection
}

pub(super) struct Ingress {
    socket: UdpSocket,
    public: SocketAddrV4,
    state: Mutex<State>,
    upgrades: Arc<Semaphore>,
}

#[derive(Default)]
struct State {
    next_id: u64,
    sessions: HashMap<u64, Session>,
    routes: HashMap<String, u64>,
    flows: HashMap<SocketAddr, Flow>,
}

struct Session {
    tunnel: TokenId,
    tx: mpsc::Sender<Frame>,
    routes: HashSet<String>,
    endpoints: HashMap<u64, SocketAddr>,
}

struct SessionGuard<'a> {
    ingress: &'a Ingress,
    id: u64,
    _permit: OwnedSemaphorePermit,
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.ingress.state.lock().unwrap();
        if let Some(session) = state.sessions.remove(&self.id) {
            for route in session.routes {
                state.routes.remove(&route);
            }
            for endpoint in session.endpoints.values() {
                state.flows.remove(endpoint);
            }
        }
    }
}

struct Flow {
    id: u64,
    session: u64,
    recipient: String,
    sender: String,
    confirmed: bool,
    expires: Instant,
    pending: Vec<([u8; 12], Instant)>,
}

enum Binding<'a> {
    Request(&'a str, &'a str, [u8; 12]),
    Success([u8; 12]),
}

fn binding(packet: &[u8]) -> Option<Binding<'_>> {
    if packet.len() < 20 || packet[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return None;
    }
    let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if length % 4 != 0 || length != packet.len() - 20 {
        return None;
    }
    let transaction = packet[8..20].try_into().ok()?;
    match packet[..2] {
        [1, 1] => Some(Binding::Success(transaction)),
        [0, 1] => {
            let mut attributes = &packet[20..];
            let mut names = None;
            while let [hi, lo, len_hi, len_lo, rest @ ..] = attributes {
                let len = u16::from_be_bytes([*len_hi, *len_lo]) as usize;
                let value = rest.get(..len)?;
                attributes = rest.get(len.next_multiple_of(4)..)?;
                if [*hi, *lo] == [0, 6] {
                    let (recipient, sender) = std::str::from_utf8(value).ok()?.split_once(':')?;
                    if names.is_some() || !valid_ufrag(recipient) || !valid_ufrag(sender) {
                        return None;
                    }
                    names = Some((recipient, sender));
                }
            }
            if !attributes.is_empty() {
                return None;
            }
            let (recipient, sender) = names?;
            Some(Binding::Request(recipient, sender, transaction))
        }
        _ => None,
    }
}

fn valid_ufrag(value: &str) -> bool {
    (4..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

fn media_packet(packet: &[u8]) -> bool {
    // RFC 7983 demultiplexing for DTLS and RTP/RTCP on an ICE transport.
    matches!(packet.first().copied(), Some(20..=63 | 128..=191))
}

struct Frame {
    kind: u8,
    body: Vec<u8>,
}

impl Frame {
    async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let kind = reader.read_u8().await?;
        let length = reader.read_u16().await? as usize;
        ensure!(length <= MAX_FRAME, "oversized relay media frame");
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await?;
        Ok(Self { kind, body })
    }

    async fn write(self, writer: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
        let mut frame = Vec::with_capacity(3 + self.body.len());
        frame.push(self.kind);
        frame.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        frame.extend_from_slice(&self.body);
        time::timeout(IO_TIMEOUT, writer.write_all(&frame)).await??;
        Ok(())
    }
}

impl State {
    fn allocate_id(&mut self) -> u64 {
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("relay media identifiers exhausted");
        self.next_id
    }

    fn remove_flow(&mut self, endpoint: SocketAddr) {
        if let Some(flow) = self.flows.remove(&endpoint) {
            self.sessions
                .get_mut(&flow.session)
                .unwrap()
                .endpoints
                .remove(&flow.id);
        }
    }

    fn register(&mut self, session: u64, body: &[u8]) -> Result<()> {
        let text = std::str::from_utf8(body)?;
        let routes: HashSet<_> = text.split_terminator('\n').map(str::to_owned).collect();
        ensure!(
            routes.len() <= MAX_ROUTES && routes.iter().all(|route| valid_ufrag(route)),
            "invalid ICE route set"
        );
        ensure!(
            routes
                .iter()
                .all(|route| self.routes.get(route).is_none_or(|owner| *owner == session)),
            "ICE route collision"
        );

        let current = self
            .sessions
            .get_mut(&session)
            .context("closed media session")?;
        let stale: Vec<_> = current
            .endpoints
            .values()
            .copied()
            .filter(|endpoint| !routes.contains(&self.flows[endpoint].recipient))
            .collect();
        for route in current.routes.difference(&routes) {
            self.routes.remove(route);
        }
        for route in routes.difference(&current.routes) {
            self.routes.insert(route.clone(), session);
        }
        current.routes = routes;
        for endpoint in stale {
            self.remove_flow(endpoint);
        }
        Ok(())
    }

    fn dispatch(&mut self, endpoint: SocketAddr, packet: &[u8], now: Instant) {
        if self
            .flows
            .get(&endpoint)
            .is_some_and(|flow| flow.expires <= now)
        {
            self.remove_flow(endpoint);
        }

        if let Some(Binding::Request(recipient, sender, transaction)) = binding(packet) {
            let Some(&session) = self.routes.get(recipient) else {
                return;
            };
            if let Some(flow) = self.flows.get(&endpoint) {
                if flow.session != session || flow.recipient != recipient || flow.sender != sender {
                    return;
                }
            } else {
                if self.sessions[&session].endpoints.len() >= MAX_FLOWS {
                    return;
                }
                let id = self.allocate_id();
                self.sessions
                    .get_mut(&session)
                    .unwrap()
                    .endpoints
                    .insert(id, endpoint);
                self.flows.insert(
                    endpoint,
                    Flow {
                        id,
                        session,
                        recipient: recipient.to_owned(),
                        sender: sender.to_owned(),
                        confirmed: false,
                        expires: now + PENDING_TTL,
                        pending: Vec::new(),
                    },
                );
            }
            let flow = self.flows.get_mut(&endpoint).unwrap();
            flow.pending
                .retain(|(id, deadline)| *deadline > now && *id != transaction);
            if flow.pending.len() == MAX_TRANSACTIONS {
                flow.pending.remove(0);
            }
            flow.pending.push((transaction, now + PENDING_TTL));
        } else if !media_packet(packet)
            || !self.flows.get(&endpoint).is_some_and(|flow| flow.confirmed)
        {
            return;
        }

        let flow = &self.flows[&endpoint];
        let mut body = Vec::with_capacity(8 + packet.len());
        body.extend_from_slice(&flow.id.to_be_bytes());
        body.extend_from_slice(packet);
        let _ = self.sessions[&flow.session].tx.try_send(Frame {
            kind: DATAGRAM,
            body,
        });
    }

    fn reply(&mut self, session: u64, id: u64, packet: &[u8], now: Instant) -> Option<SocketAddr> {
        let endpoint = *self.sessions.get(&session)?.endpoints.get(&id)?;
        let flow = self.flows.get_mut(&endpoint)?;
        if flow.expires <= now {
            return None;
        }
        if let Some(Binding::Success(transaction)) = binding(packet) {
            let index = flow
                .pending
                .iter()
                .position(|(id, deadline)| *id == transaction && *deadline > now)?;
            flow.pending.swap_remove(index);
            flow.confirmed = true;
            flow.expires = now + CONSENT_TTL;
        } else if !flow.confirmed || !media_packet(packet) {
            return None;
        }
        Some(endpoint)
    }
}

impl Ingress {
    pub(super) async fn bind(bind: SocketAddrV4, public: SocketAddrV4) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            socket: UdpSocket::bind(bind)
                .await
                .context("failed to listen at relay.media_bind_addr")?,
            public,
            state: Mutex::default(),
            upgrades: Arc::new(Semaphore::new(MAX_SESSIONS)),
        }))
    }

    pub(super) async fn run(&self) -> anyhow::Error {
        let mut packet = [0; MAX_PACKET + 1];
        let mut reap = time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut packet) => match received {
                    Ok((length, endpoint)) if length <= MAX_PACKET => {
                        self.state.lock().unwrap().dispatch(endpoint, &packet[..length], Instant::now());
                    }
                    Ok(_) => {}
                    Err(error) => return error.into(),
                },
                _ = reap.tick() => {
                    let now = Instant::now();
                    let mut state = self.state.lock().unwrap();
                    let stale: Vec<_> = state.flows.iter()
                        .filter_map(|(endpoint, flow)| (flow.expires <= now).then_some(*endpoint))
                        .collect();
                    for endpoint in stale {
                        state.remove_flow(endpoint);
                    }
                }
            }
        }
    }

    pub(super) async fn serve(
        &self,
        mut stream: TcpStream,
        tunnel: TokenId,
        verifier: &TokenId,
    ) -> Result<()> {
        stream.set_nodelay(true)?;
        let permit = self
            .upgrades
            .clone()
            .try_acquire_owned()
            .context("relay media capacity exhausted")?;
        time::timeout(IO_TIMEOUT, async {
            let mut nonce = [0; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: pioneer-call-media-v1\r\n\r\n").await?;
            stream.write_all(&nonce).await?;
            let mut proof = [0; 32];
            stream.read_exact(&mut proof).await?;
            let expected: TokenId = Sha256::new()
                .chain_update(b"pioneer-call-media/v1\0")
                .chain_update(verifier)
                .chain_update(nonce)
                .finalize().into();
            ensure!(bool::from(proof.ct_eq(&expected)), "relay media authorization failed");
            Ok::<_, anyhow::Error>(())
        }).await??;

        let (tx, mut rx) = mpsc::channel(128);
        let id = {
            let mut state = self.state.lock().unwrap();
            ensure!(
                state
                    .sessions
                    .values()
                    .filter(|session| session.tunnel == tunnel)
                    .count()
                    < MAX_SESSIONS_PER_TUNNEL,
                "tunnel media capacity exhausted"
            );
            let id = state.allocate_id();
            state.sessions.insert(
                id,
                Session {
                    tunnel,
                    tx: tx.clone(),
                    routes: HashSet::new(),
                    endpoints: HashMap::new(),
                },
            );
            id
        };
        let _session = SessionGuard {
            ingress: self,
            id,
            _permit: permit,
        };
        let mut address = self.public.ip().octets().to_vec();
        address.extend_from_slice(&self.public.port().to_be_bytes());
        time::timeout(IO_TIMEOUT, stream.write_all(&address)).await??;

        let (mut reader, mut writer) = stream.into_split();
        let from_gateway = async {
            loop {
                let frame = time::timeout(FRAME_TIMEOUT, Frame::read(&mut reader)).await??;
                match frame.kind {
                    REGISTER => {
                        self.state.lock().unwrap().register(id, &frame.body)?;
                        time::timeout(
                            IO_TIMEOUT,
                            tx.send(Frame {
                                kind: ACK,
                                body: Vec::new(),
                            }),
                        )
                        .await??;
                    }
                    DATAGRAM if (9..=8 + MAX_PACKET).contains(&frame.body.len()) => {
                        let flow = u64::from_be_bytes(frame.body[..8].try_into()?);
                        let packet = &frame.body[8..];
                        let mut state = self.state.lock().unwrap();
                        if let Some(endpoint) = state.reply(id, flow, packet, Instant::now()) {
                            // A route cannot be reassigned between validation and send.
                            let _ = self.socket.try_send_to(packet, endpoint);
                        }
                    }
                    KEEPALIVE if frame.body.is_empty() => {}
                    _ => anyhow::bail!("invalid relay media frame"),
                }
            }
        };
        let to_gateway = async {
            let mut heartbeat = time::interval(Duration::from_secs(10));
            heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            loop {
                let frame = tokio::select! {
                    _ = heartbeat.tick() => Frame { kind: KEEPALIVE, body: Vec::new() },
                    frame = rx.recv() => match frame {
                        Some(frame) => frame,
                        None => return Ok(()),
                    },
                };
                frame.write(&mut writer).await?;
            }
        };
        tokio::select! {
            result = from_gateway => result,
            result = to_gateway => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        handle_control_connection, handle_ingress_connection, ControlChannelMap, RelayRegistry,
    };
    use super::*;
    use crate::{config::RelayTunnelConfig, protocol, token};
    use tokio::{
        net::TcpListener,
        sync::{watch, RwLock},
    };

    fn request(recipient: &str, sender: &str, id: u8) -> Vec<u8> {
        let username = format!("{recipient}:{sender}");
        let padded = username.len().next_multiple_of(4);
        let mut packet = vec![0; 24 + padded];
        packet[..2].copy_from_slice(&[0, 1]);
        packet[2..4].copy_from_slice(&((4 + padded) as u16).to_be_bytes());
        packet[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        packet[8..20].fill(id);
        packet[20..22].copy_from_slice(&[0, 6]);
        packet[22..24].copy_from_slice(&(username.len() as u16).to_be_bytes());
        packet[24..24 + username.len()].copy_from_slice(username.as_bytes());
        packet
    }

    fn reply(id: u8) -> Vec<u8> {
        let mut response = vec![0; 20];
        response[..2].copy_from_slice(&[1, 1]);
        response[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response[8..20].fill(id);
        response
    }

    async fn read_data(stream: &mut TcpStream) -> Frame {
        time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = Frame::read(stream).await.unwrap();
                if frame.kind != KEEPALIVE {
                    break frame;
                }
            }
        })
        .await
        .unwrap()
    }

    struct RelayFixture {
        registry: Arc<RelayRegistry>,
        channels: Arc<RwLock<ControlChannelMap>>,
        ingress: Arc<Ingress>,
        shutdown: watch::Sender<()>,
    }

    impl RelayFixture {
        fn new(ingress: Arc<Ingress>) -> Self {
            let tunnels = [1, 2].map(|token| RelayTunnelConfig {
                id: format!("gateway{token}"),
                url: format!("https://gateway{token}.example.invalid/pioneer/")
                    .parse()
                    .unwrap(),
                token_hash: hex::encode([token; 32]).into(),
                nodelay: Some(true),
            });
            Self {
                registry: Arc::new(RelayRegistry::from_tunnels(&tunnels).unwrap()),
                channels: Arc::new(RwLock::new(ControlChannelMap::new())),
                ingress,
                shutdown: watch::channel(()).0,
            }
        }

        async fn control(&self, token: u8) -> TcpStream {
            let (mut client, server) = pair().await;
            let registry = self.registry.clone();
            let channels = self.channels.clone();
            let task = tokio::spawn(handle_control_connection(server, registry, channels, 1));
            let hello = protocol::Hello::ControlChannelHello(
                protocol::CURRENT_PROTO_VERSION,
                token::routing_id_for_token_hash(&[token; 32]),
            );
            client
                .write_all(&bincode::serialize(&hello).unwrap())
                .await
                .unwrap();
            let protocol::Hello::ControlChannelHello(_, nonce) =
                protocol::read_hello(&mut client).await.unwrap()
            else {
                panic!("expected relay control challenge");
            };
            let proof = protocol::Auth(token::response_for_token_hash(&[token; 32], &nonce));
            client
                .write_all(&bincode::serialize(&proof).unwrap())
                .await
                .unwrap();
            assert!(matches!(
                protocol::read_ack(&mut client).await.unwrap(),
                protocol::Ack::Ok
            ));
            assert_eq!(
                protocol::read_control_metadata(&mut client)
                    .await
                    .unwrap()
                    .unwrap(),
                format!("https://gateway{token}.example.invalid/pioneer/")
            );
            task.await.unwrap().unwrap();
            client
        }

        async fn open(
            &self,
            host: u8,
            proof_key: u8,
        ) -> (TcpStream, tokio::task::JoinHandle<Result<()>>) {
            let (mut stream, server) = pair().await;
            let task = tokio::spawn(handle_ingress_connection(
                server,
                self.registry.clone(),
                self.channels.clone(),
                8192,
                Some(self.ingress.clone()),
                self.shutdown.subscribe(),
            ));
            let request = format!("GET /_pioneer/call-media/v1 HTTP/1.1\r\nHost: gateway{host}.example.invalid\r\nConnection: Upgrade\r\nUpgrade: pioneer-call-media-v1\r\n\r\n");
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
            }
            assert!(headers.starts_with(b"HTTP/1.1 101 "));
            let mut nonce = [0; 32];
            stream.read_exact(&mut nonce).await.unwrap();
            let proof = Sha256::new()
                .chain_update(b"pioneer-call-media/v1\0")
                .chain_update([proof_key; 32])
                .chain_update(nonce)
                .finalize();
            stream.write_all(&proof).await.unwrap();
            (stream, task)
        }
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn register(stream: &mut TcpStream, routes: &str) {
        Frame {
            kind: REGISTER,
            body: routes.as_bytes().to_vec(),
        }
        .write(stream)
        .await
        .unwrap();
    }

    async fn bind(
        peer: &UdpSocket,
        public: SocketAddr,
        stream: &mut TcpStream,
        name: &str,
        transaction: u8,
    ) -> [u8; 8] {
        let request = request(name, "client", transaction);
        peer.send_to(&request, public).await.unwrap();
        let frame = read_data(stream).await;
        assert_eq!(frame.kind, DATAGRAM);
        assert_eq!(frame.body[8..], request);
        let flow: [u8; 8] = frame.body[..8].try_into().unwrap();
        let response = reply(transaction);
        send_packet(stream, &flow, &response).await;
        let mut packet = [0; MAX_PACKET];
        let (len, from) = time::timeout(Duration::from_secs(2), peer.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from, public);
        assert_eq!(packet[..len], response);
        flow
    }

    async fn expect_closed(stream: &mut TcpStream) {
        time::timeout(Duration::from_secs(2), async {
            loop {
                match stream.read_u8().await {
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Ok(KEEPALIVE) => assert_eq!(stream.read_u16().await.unwrap(), 0),
                    other => panic!("expected heartbeat or closed media stream, got {other:?}"),
                }
            }
        })
        .await
        .unwrap();
    }

    async fn send_packet(stream: &mut TcpStream, flow: &[u8; 8], data: &[u8]) {
        let mut body = flow.to_vec();
        body.extend_from_slice(data);
        Frame {
            kind: DATAGRAM,
            body,
        }
        .write(stream)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn two_tunnels_share_udp_and_keep_isolated_ice_generations() {
        let ingress = Ingress::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:2346".parse().unwrap(),
        )
        .await
        .unwrap();
        let public = ingress.socket.local_addr().unwrap();
        let public_task = tokio::spawn({
            let ingress = ingress.clone();
            async move { ingress.run().await }
        });
        let relay = RelayFixture::new(ingress.clone());
        let control_a = relay.control(1).await;
        let _control_b = relay.control(2).await;
        let (mut denied, denied_task) = relay.open(1, 2).await;
        assert_eq!(denied.read(&mut [0]).await.unwrap(), 0);
        assert!(denied_task.await.unwrap().is_err());
        let (mut a, a_task) = relay.open(1, 1).await;
        let (mut b, b_task) = relay.open(2, 2).await;
        let mut address_a = [0; 6];
        let mut address_b = [0; 6];
        a.read_exact(&mut address_a).await.unwrap();
        b.read_exact(&mut address_b).await.unwrap();
        assert_eq!(address_a, address_b);

        register(&mut a, "gatewayA\npublishA\n").await;
        assert_eq!(read_data(&mut a).await.kind, ACK);
        register(&mut b, "gatewayB\n").await;
        assert_eq!(read_data(&mut b).await.kind, ACK);
        let peer_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let publisher = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (flow_a, flow_b) = tokio::join!(
            bind(&peer_a, public, &mut a, "gatewayA", 1),
            bind(&peer_b, public, &mut b, "gatewayB", 2),
        );
        bind(&publisher, public, &mut a, "publishA", 3).await;

        // A source that already belongs to Gateway A cannot move to Gateway B.
        peer_a
            .send_to(&request("gatewayB", "client", 4), public)
            .await
            .unwrap();
        // Gateway A cannot inject a datagram for Gateway B's flow identifier.
        send_packet(&mut a, &flow_b, &[0x80, 1]).await;
        let mut data = [0; MAX_PACKET];
        assert!(
            time::timeout(Duration::from_millis(80), peer_b.recv(&mut data))
                .await
                .is_err()
        );

        let media_a = [0x80, 42];
        let media_b = [0x80, 56];
        send_packet(&mut a, &flow_a, &media_a).await;
        send_packet(&mut b, &flow_b, &media_b).await;
        assert_eq!(
            time::timeout(Duration::from_secs(1), peer_a.recv(&mut data))
                .await
                .unwrap()
                .unwrap(),
            2
        );
        assert_eq!(data[..2], media_a);
        assert_eq!(
            time::timeout(Duration::from_secs(1), peer_b.recv(&mut data))
                .await
                .unwrap()
                .unwrap(),
            2
        );
        assert_eq!(data[..2], media_b);

        // A network change can introduce a new source while the old
        // consent entry is still live. Other tunnels keep their media route.
        let rebound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rebound_flow = bind(&rebound, public, &mut a, "gatewayA", 6).await;
        assert_ne!(rebound_flow, flow_a);
        send_packet(&mut a, &rebound_flow, &media_a).await;
        send_packet(&mut b, &flow_b, &media_b).await;
        for (peer, expected) in [(&rebound, media_a), (&peer_b, media_b)] {
            let len = time::timeout(Duration::from_secs(1), peer.recv(&mut data))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&data[..len], &expected);
        }

        register(&mut a, "restartA\npublishA\n").await;
        assert_eq!(read_data(&mut a).await.kind, ACK);
        assert_ne!(bind(&peer_a, public, &mut a, "restartA", 5).await, flow_a);

        register(&mut b, "restartA\n").await;
        expect_closed(&mut b).await;
        assert!(b_task.await.unwrap().is_err());
        drop(control_a);
        expect_closed(&mut a).await;
        assert!(a_task.await.unwrap().is_ok());
        let state = ingress.state.lock().unwrap();
        assert!(state.flows.is_empty() && state.routes.is_empty() && state.sessions.is_empty());
        public_task.abort();
    }
}
