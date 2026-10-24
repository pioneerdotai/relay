pub const HASH_WIDTH_IN_BYTES: usize = 32;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

type ProtocolVersion = u8;
const _PROTO_V0: u8 = 0u8;
const PROTO_V2: u8 = 2u8;

pub const CURRENT_PROTO_VERSION: ProtocolVersion = PROTO_V2;

pub type Digest = [u8; HASH_WIDTH_IN_BYTES];

#[derive(Deserialize, Serialize, Debug)]
pub enum Hello {
    ControlChannelHello(ProtocolVersion, Digest), // routing digest or a nonce
    DataChannelHello(ProtocolVersion, Digest),    // session key provided by CreateDataChannel
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Auth(pub Digest);

#[derive(Deserialize, Serialize, Debug)]
pub enum Ack {
    Ok,
    ServiceNotExist,
    AuthFailed,
}

impl std::fmt::Display for Ack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Ack::Ok => "Ok",
                Ack::ServiceNotExist => "Service not exist",
                Ack::AuthFailed => "Incorrect token",
            }
        )
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub enum ControlChannelCmd {
    CreateDataChannel,
    HeartBeat,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum DataChannelCmd {
    StartForwardTcp,
    StartForwardUdp,
}

type UdpPacketLen = u16; // `u16` should be enough for any practical UDP traffic on the Internet
#[derive(Deserialize, Serialize, Debug)]
struct UdpHeader {
    from: SocketAddr,
    len: UdpPacketLen,
}

#[derive(Debug)]
pub struct UdpTraffic {
    pub from: SocketAddr,
    pub data: Bytes,
}

impl UdpTraffic {
    pub async fn write<T: AsyncWrite + Unpin>(&self, writer: &mut T) -> Result<()> {
        let hdr = UdpHeader {
            from: self.from,
            len: self.data.len() as UdpPacketLen,
        };

        let v = bincode::serialize(&hdr).unwrap();

        trace!("Write {:?} of length {}", hdr, v.len());
        writer.write_u8(v.len() as u8).await?;
        writer.write_all(&v).await?;

        writer.write_all(&self.data).await?;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn write_slice<T: AsyncWrite + Unpin>(
        writer: &mut T,
        from: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        let hdr = UdpHeader {
            from,
            len: data.len() as UdpPacketLen,
        };

        let v = bincode::serialize(&hdr).unwrap();

        trace!("Write {:?} of length {}", hdr, v.len());
        writer.write_u8(v.len() as u8).await?;
        writer.write_all(&v).await?;

        writer.write_all(data).await?;

        Ok(())
    }

    pub async fn read<T: AsyncRead + Unpin>(reader: &mut T, hdr_len: u8) -> Result<UdpTraffic> {
        let mut buf = vec![0; hdr_len as usize];
        reader
            .read_exact(&mut buf)
            .await
            .with_context(|| "Failed to read udp header")?;

        let hdr: UdpHeader =
            bincode::deserialize(&buf).with_context(|| "Failed to deserialize UdpHeader")?;

        trace!("hdr {:?}", hdr);

        let mut data = BytesMut::new();
        data.resize(hdr.len as usize, 0);
        reader.read_exact(&mut data).await?;

        Ok(UdpTraffic {
            from: hdr.from,
            data: data.freeze(),
        })
    }
}

pub fn digest(data: &[u8]) -> Digest {
    use sha2::{Digest, Sha256};
    let d = Sha256::new().chain_update(data).finalize();
    d.into()
}

struct PacketLength {
    hello: usize,
    ack: usize,
    auth: usize,
    c_cmd: usize,
    d_cmd: usize,
}

impl PacketLength {
    pub fn new() -> PacketLength {
        let username = "default";
        let d = digest(username.as_bytes());
        let hello = bincode::serialized_size(&Hello::ControlChannelHello(CURRENT_PROTO_VERSION, d))
            .unwrap() as usize;
        let c_cmd =
            bincode::serialized_size(&ControlChannelCmd::CreateDataChannel).unwrap() as usize;
        let d_cmd = bincode::serialized_size(&DataChannelCmd::StartForwardTcp).unwrap() as usize;
        let ack = Ack::Ok;
        let ack = bincode::serialized_size(&ack).unwrap() as usize;

        let auth = bincode::serialized_size(&Auth(d)).unwrap() as usize;
        PacketLength {
            hello,
            ack,
            auth,
            c_cmd,
            d_cmd,
        }
    }
}

lazy_static! {
    static ref PACKET_LEN: PacketLength = PacketLength::new();
}

pub async fn read_hello<T: AsyncRead + AsyncWrite + Unpin>(conn: &mut T) -> Result<Hello> {
    let mut buf = vec![0u8; PACKET_LEN.hello];
    conn.read_exact(&mut buf)
        .await
        .with_context(|| "Failed to read hello")?;
    let hello = bincode::deserialize(&buf).with_context(|| "Failed to deserialize hello")?;

    match hello {
        Hello::ControlChannelHello(v, _) => {
            if v != CURRENT_PROTO_VERSION {
                bail!(
                    "Protocol version mismatched. Expected {}, got {}. Please update `rathole`.",
                    CURRENT_PROTO_VERSION,
                    v
                );
            }
        }
        Hello::DataChannelHello(v, _) => {
            if v != CURRENT_PROTO_VERSION {
                bail!(
                    "Protocol version mismatched. Expected {}, got {}. Please update `rathole`.",
                    CURRENT_PROTO_VERSION,
                    v
                );
            }
        }
    }

    Ok(hello)
}

pub async fn read_auth<T: AsyncRead + AsyncWrite + Unpin>(conn: &mut T) -> Result<Auth> {
    let mut buf = vec![0u8; PACKET_LEN.auth];
    conn.read_exact(&mut buf)
        .await
        .with_context(|| "Failed to read auth")?;
    bincode::deserialize(&buf).with_context(|| "Failed to deserialize auth")
}

pub async fn read_ack<T: AsyncRead + AsyncWrite + Unpin>(conn: &mut T) -> Result<Ack> {
    let mut bytes = vec![0u8; PACKET_LEN.ack];
    conn.read_exact(&mut bytes)
        .await
        .with_context(|| "Failed to read ack")?;
    bincode::deserialize(&bytes).with_context(|| "Failed to deserialize ack")
}

// V2 retains fixed-size Hello/Auth/Ack packets. After Ack::Ok, a u16 big-endian
// length frames the authenticated UTF-8 public URL. Zero denotes a legacy
// service server without public URL metadata. Never parse it as a control cmd.
pub const MAX_PUBLIC_BASE_URL_BYTES: usize = 8192;

pub fn validate_public_base_url(value: &str) -> Result<()> {
    if value.len() > MAX_PUBLIC_BASE_URL_BYTES
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        bail!("invalid public relay URL");
    }
    let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid public relay URL"))?;
    let unspecified = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_unspecified(),
        Some(url::Host::Ipv6(address)) => address.is_unspecified(),
        _ => false,
    };
    if url.scheme() != "https"
        || url.host_str().is_none()
        || unspecified
        || url.port() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("invalid public relay URL");
    }
    Ok(())
}

pub async fn write_control_metadata<T: AsyncWrite + Unpin>(
    conn: &mut T,
    public_base_url: Option<&str>,
) -> Result<()> {
    if let Some(value) = public_base_url {
        validate_public_base_url(value)?;
    }
    let bytes = public_base_url.unwrap_or_default().as_bytes();
    conn.write_u16(bytes.len() as u16).await?;
    conn.write_all(bytes).await?;
    Ok(())
}

pub async fn read_control_metadata<T: AsyncRead + Unpin>(conn: &mut T) -> Result<Option<String>> {
    let len = usize::from(
        conn.read_u16()
            .await
            .context("failed to read control metadata length")?,
    );
    if len > MAX_PUBLIC_BASE_URL_BYTES {
        bail!("public relay URL exceeds protocol limit");
    }
    if len == 0 {
        return Ok(None);
    }
    let mut bytes = vec![0; len];
    conn.read_exact(&mut bytes)
        .await
        .context("failed to read control metadata")?;
    let value = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("invalid public relay URL encoding"))?;
    validate_public_base_url(&value)?;
    Ok(Some(value))
}

pub async fn read_control_cmd<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
) -> Result<ControlChannelCmd> {
    let mut bytes = vec![0u8; PACKET_LEN.c_cmd];
    conn.read_exact(&mut bytes)
        .await
        .with_context(|| "Failed to read cmd")?;
    bincode::deserialize(&bytes).with_context(|| "Failed to deserialize control cmd")
}

pub async fn read_data_cmd<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
) -> Result<DataChannelCmd> {
    let mut bytes = vec![0u8; PACKET_LEN.d_cmd];
    conn.read_exact(&mut bytes)
        .await
        .with_context(|| "Failed to read cmd")?;
    bincode::deserialize(&bytes).with_context(|| "Failed to deserialize data cmd")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authenticated_metadata_preserves_prefix_and_next_control_packet() {
        let (mut writer, mut reader) = tokio::io::duplex(16384);
        let base = "https://[2001:db8::1]:8443/pioneer/edge/";
        writer
            .write_all(&bincode::serialize(&Ack::Ok).unwrap())
            .await
            .unwrap();
        write_control_metadata(&mut writer, Some(base))
            .await
            .unwrap();
        writer
            .write_all(&bincode::serialize(&ControlChannelCmd::HeartBeat).unwrap())
            .await
            .unwrap();
        assert!(matches!(read_ack(&mut reader).await.unwrap(), Ack::Ok));
        assert_eq!(
            read_control_metadata(&mut reader).await.unwrap().as_deref(),
            Some(base)
        );
        assert!(matches!(
            read_control_cmd(&mut reader).await.unwrap(),
            ControlChannelCmd::HeartBeat
        ));

        write_control_metadata(&mut writer, None).await.unwrap();
        assert_eq!(read_control_metadata(&mut reader).await.unwrap(), None);
    }

    #[tokio::test]
    async fn invalid_control_metadata_and_old_version_are_rejected() {
        for bytes in [
            b"https://user:secret@example.invalid/".as_slice(),
            b"https://example.invalid/?query".as_slice(),
            b"https://example.invalid/#fragment".as_slice(),
            b"relay.example.invalid:2333".as_slice(),
            b"http://example.invalid/".as_slice(),
            b"https://0.0.0.0/".as_slice(),
            b"https://[::]/".as_slice(),
            &[0xff, 0xfe],
        ] {
            let (mut writer, mut reader) = tokio::io::duplex(16384);
            writer.write_u16(bytes.len() as u16).await.unwrap();
            writer.write_all(bytes).await.unwrap();
            assert!(read_control_metadata(&mut reader).await.is_err());
        }
        let (mut writer, mut reader) = tokio::io::duplex(16384);
        writer
            .write_u16((MAX_PUBLIC_BASE_URL_BYTES + 1) as u16)
            .await
            .unwrap();
        assert!(read_control_metadata(&mut reader).await.is_err());

        let (mut writer, mut reader) = tokio::io::duplex(16384);
        writer.write_u16(100).await.unwrap();
        writer.write_all(b"truncated").await.unwrap();
        drop(writer);
        assert!(read_control_metadata(&mut reader).await.is_err());

        let (mut writer, mut reader) = tokio::io::duplex(16384);
        writer
            .write_all(&bincode::serialize(&Hello::ControlChannelHello(1, [0; 32])).unwrap())
            .await
            .unwrap();
        assert!(read_hello(&mut reader).await.is_err());
    }
}
