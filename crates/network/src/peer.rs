//! Async peer connection and handshake. Port of parts of src/net.cpp and src/net_processing.cpp.
//!
//! Covers outbound connect, the version/verack handshake, ping/pong and a
//! read/write loop. `inv`, `getdata`, `headers`, `getheaders` and `addr` are
//! passed to the caller unparsed.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use btc_consensus::ChainParams;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::message::{
    decode_payload, encode_message, MessageError, MessageHeader, NetworkMessage, HEADER_SIZE,
};

/// `PROTOCOL_VERSION` from `node/protocol_version.h`.
pub const PROTOCOL_VERSION: u32 = 70017;
/// `MIN_PEER_PROTO_VERSION` from `node/protocol_version.h`.
pub const MIN_PEER_PROTO_VERSION: u32 = 31800;
/// Our choice of TCP connect timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Our choice of handshake timeout. Covers both version and verack.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Capacity of the channel from the reader task to the run loop.
const FRAME_CHANNEL_CAPACITY: usize = 64;

/// Errors from connecting to or talking with a peer.
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("message error: {0}")]
    Message(#[from] MessageError),
    #[error("connect to {0} timed out")]
    ConnectTimeout(SocketAddr),
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("peer sent a second version message")]
    DuplicateVersion,
    #[error("peer protocol version {0} is below the minimum")]
    ProtocolVersionTooOld(u32),
    #[error("peer nonce matches ours: connected to ourselves")]
    SelfConnection,
    #[error("connection closed by peer")]
    Disconnected,
}

/// Values we announce in our `version` message.
#[derive(Clone, Debug)]
pub struct LocalVersion {
    pub services: ServiceFlags,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

impl Default for LocalVersion {
    fn default() -> Self {
        Self {
            // We do not serve blocks or transactions yet, so no service bits.
            services: ServiceFlags::NONE,
            user_agent: format!("/btc-rust:{}/", env!("CARGO_PKG_VERSION")),
            start_height: 0,
            relay: true,
        }
    }
}

/// What we learned about the peer during the handshake.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub version: u32,
    pub services: ServiceFlags,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

/// One connection to a peer on a given network.
///
/// `S` is the transport. Use `Peer<TcpStream>` for real connections, or any
/// in-memory stream in tests.
pub struct Peer<S> {
    addr: SocketAddr,
    magic: [u8; 4],
    /// Random nonce sent in our `version`, used to detect self-connections.
    nonce: u64,
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
}

impl Peer<TcpStream> {
    /// Opens an outbound TCP connection to `addr`.
    pub async fn connect(addr: SocketAddr, chain: &ChainParams) -> Result<Self, PeerError> {
        Self::connect_via_proxy(addr, None, chain).await
    }

    /// Opens an outbound connection, optionally tunnelled through a
    /// SOCKS5 proxy (Tor's SOCKS port, `-proxy=`). The proxy resolves
    /// nothing here: `addr` is always an IP, sent with ATYP=IPv4/IPv6.
    /// Onion peers are not supported until the address table learns
    /// hostnames.
    pub async fn connect_via_proxy(
        addr: SocketAddr,
        proxy: Option<SocketAddr>,
        chain: &ChainParams,
    ) -> Result<Self, PeerError> {
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(proxy.unwrap_or(addr)))
            .await
            .map_err(|_| PeerError::ConnectTimeout(proxy.unwrap_or(addr)))??;
        if let Some(proxy) = proxy {
            socks5_handshake(&mut stream, addr).await?;
            let _ = proxy;
        }
        Ok(Self::from_stream(stream, addr, chain))
    }
}

/// SOCKS5 no-auth handshake and CONNECT. `stream` is already connected to
/// the proxy; on success the stream speaks plain TCP to `dest`.
async fn socks5_handshake<S>(stream: &mut S, dest: SocketAddr) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::io::{Error, ErrorKind};
    let mut buf = vec![0x05u8, 0x01, 0x00];
    stream.write_all(&buf).await?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf != [0x05, 0x00] {
        return Err(Error::new(ErrorKind::InvalidData, "SOCKS5 proxy requires authentication"));
    }
    let mut request = vec![0x05u8, 0x01, 0x00];
    match dest.ip() {
        std::net::IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&dest.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = vec![0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(Error::new(ErrorKind::Other, format!("SOCKS5 CONNECT failed: rep={}", reply[1])));
    }
    // Consume the bound address: 4 or 16 bytes for IPv4/IPv6, else skip
    // the length-prefixed domain form.
    let atyp = reply[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        other => return Err(Error::new(ErrorKind::InvalidData, format!("SOCKS5 bad ATYP {other}"))),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

impl<S> Peer<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Wraps an already-open stream. `addr` is the remote address for logging and `PeerInfo`.
    pub fn from_stream(stream: S, addr: SocketAddr, chain: &ChainParams) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            addr,
            magic: chain.magic,
            nonce: random_nonce(),
            reader,
            writer,
        }
    }

    /// Runs the version/verack exchange and returns what the peer announced.
    ///
    /// We send our `version` first. Then we answer the peer's `version` with
    /// `verack` and wait for its `verack`. Like Core, we ignore other messages
    /// until both have arrived.
    pub async fn handshake(&mut self, local: &LocalVersion) -> Result<PeerInfo, PeerError> {
        timeout(HANDSHAKE_TIMEOUT, self.run_handshake(local))
            .await
            .map_err(|_| PeerError::HandshakeTimeout)?
    }

    async fn run_handshake(&mut self, local: &LocalVersion) -> Result<PeerInfo, PeerError> {
        let ours = self.version_message(local);
        self.send(&NetworkMessage::Version(ours)).await?;

        let mut remote: Option<VersionMessage> = None;
        let mut got_verack = false;
        while remote.is_none() || !got_verack {
            match self.recv().await? {
                NetworkMessage::Version(version) => {
                    if remote.is_some() {
                        return Err(PeerError::DuplicateVersion);
                    }
                    if version.version < MIN_PEER_PROTO_VERSION {
                        return Err(PeerError::ProtocolVersionTooOld(version.version));
                    }
                    if version.nonce == self.nonce {
                        return Err(PeerError::SelfConnection);
                    }
                    self.send(&NetworkMessage::Verack).await?;
                    remote = Some(version);
                }
                NetworkMessage::Verack if remote.is_some() => got_verack = true,
                _ => {}
            }
        }

        let version = remote.expect("loop exits only after the peer's version arrived");
        Ok(PeerInfo {
            addr: self.addr,
            version: version.version,
            services: version.services,
            user_agent: version.user_agent,
            start_height: version.start_height,
            relay: version.relay,
        })
    }

    /// Writes one message to the peer.
    pub async fn send(&mut self, msg: &NetworkMessage) -> Result<(), PeerError> {
        write_frame(&mut self.writer, self.magic, msg).await
    }

    /// Reads one message from the peer.
    ///
    /// Not cancel-safe: dropping the future mid-frame loses bytes already read.
    /// Inside a `select!` loop, use [`Peer::run`] instead.
    pub async fn recv(&mut self) -> Result<NetworkMessage, PeerError> {
        read_frame(&mut self.reader, self.magic).await
    }

    /// Serves the connection after the handshake.
    ///
    /// Ping is answered with pong. Other messages go to `events`. Messages from
    /// `outbound` are written to the peer. Returns `Ok(())` when `outbound` is
    /// closed or `events` is dropped, and an error if the connection fails.
    pub async fn run(
        self,
        mut outbound: mpsc::Receiver<NetworkMessage>,
        events: mpsc::Sender<NetworkMessage>,
    ) -> Result<(), PeerError> {
        let Peer {
            magic,
            reader,
            mut writer,
            ..
        } = self;

        // The reader runs in its own task. A partly read frame must not be lost
        // when another `select!` branch wins, so `recv` cannot be used here.
        let (frames_tx, mut frames_rx) = mpsc::channel(FRAME_CHANNEL_CAPACITY);
        let reader_task = tokio::spawn(read_loop(reader, magic, frames_tx));

        let result = loop {
            tokio::select! {
                frame = frames_rx.recv() => match frame {
                    None => break Err(PeerError::Disconnected),
                    Some(Err(err)) => break Err(err),
                    Some(Ok(NetworkMessage::Ping(nonce))) => {
                        if let Err(err) = write_frame(&mut writer, magic, &NetworkMessage::Pong(nonce)).await {
                            break Err(err);
                        }
                    }
                    // Core ignores a repeated version or verack after the handshake.
                    Some(Ok(NetworkMessage::Version(_) | NetworkMessage::Verack)) => {}
                    Some(Ok(msg)) => {
                        if events.send(msg).await.is_err() {
                            break Ok(());
                        }
                    }
                },
                out = outbound.recv() => match out {
                    None => break Ok(()),
                    Some(msg) => {
                        if let Err(err) = write_frame(&mut writer, magic, &msg).await {
                            break Err(err);
                        }
                    }
                },
            }
        };

        reader_task.abort();
        result
    }

    fn version_message(&self, local: &LocalVersion) -> VersionMessage {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut msg = VersionMessage::new(
            local.services,
            timestamp,
            Address::new(&self.addr, ServiceFlags::NONE),
            Address::new(&unspecified, local.services),
            self.nonce,
            local.user_agent.clone(),
            local.start_height,
        );
        msg.version = PROTOCOL_VERSION;
        msg.relay = local.relay;
        msg
    }
}

/// Reads frames until the stream fails, forwarding each result. Stops after
/// the first error, or once the receiver is gone.
async fn read_loop<R>(
    mut reader: R,
    magic: [u8; 4],
    frames: mpsc::Sender<Result<NetworkMessage, PeerError>>,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    loop {
        let frame = read_frame(&mut reader, magic).await;
        let failed = frame.is_err();
        if frames.send(frame).await.is_err() || failed {
            return;
        }
    }
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    magic: [u8; 4],
) -> Result<NetworkMessage, PeerError> {
    let mut header_bytes = [0u8; HEADER_SIZE];
    reader
        .read_exact(&mut header_bytes)
        .await
        .map_err(read_error)?;
    let header = MessageHeader::decode(magic, &header_bytes)?;

    let mut payload = vec![0u8; header.length as usize];
    reader.read_exact(&mut payload).await.map_err(read_error)?;
    header.verify_payload(&payload)?;

    Ok(decode_payload(header.command()?, &payload)?)
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    magic: [u8; 4],
    msg: &NetworkMessage,
) -> Result<(), PeerError> {
    let bytes = encode_message(magic, msg);
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// A clean EOF in the middle of a frame means the peer hung up.
fn read_error(err: io::Error) -> PeerError {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        PeerError::Disconnected
    } else {
        PeerError::Io(err)
    }
}

/// Random 64-bit nonce for self-connection detection. The standard library
/// seeds `RandomState` randomly, so no RNG crate is needed.
fn random_nonce() -> u64 {
    RandomState::new().build_hasher().finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::p2p::{Address, ServiceFlags};
    use tokio::io::{duplex, split};

    /// Peer address used only as a label. Tests use in-memory duplex streams,
    /// so no socket is opened.
    fn label_addr() -> SocketAddr {
        "192.0.2.10:18444".parse().unwrap()
    }

    fn remote_version(nonce: u64) -> NetworkMessage {
        let addr = label_addr();
        let mut version = VersionMessage::new(
            ServiceFlags::NONE,
            0,
            Address::new(&addr, ServiceFlags::NONE),
            Address::new(&addr, ServiceFlags::NONE),
            nonce,
            "/remote:1.0/".to_string(),
            100,
        );
        version.version = PROTOCOL_VERSION;
        NetworkMessage::Version(version)
    }

    #[tokio::test]
    async fn handshake_completes_over_in_memory_stream() {
        let chain = ChainParams::regtest();
        let magic = chain.magic;
        let (ours_io, theirs_io) = duplex(1 << 16);
        let mut peer = Peer::from_stream(ours_io, label_addr(), &chain);

        let remote = async move {
            let (mut rd, mut wr) = split(theirs_io);
            let ours = read_frame(&mut rd, magic).await.unwrap();
            assert!(matches!(ours, NetworkMessage::Version(_)));
            write_frame(&mut wr, magic, &remote_version(7)).await.unwrap();
            let verack = read_frame(&mut rd, magic).await.unwrap();
            assert_eq!(verack, NetworkMessage::Verack);
            write_frame(&mut wr, magic, &NetworkMessage::Verack)
                .await
                .unwrap();
        };

        let local = LocalVersion::default();
        let (info, ()) = tokio::join!(peer.handshake(&local), remote);
        let info = info.unwrap();
        assert_eq!(info.version, PROTOCOL_VERSION);
        assert_eq!(info.user_agent, "/remote:1.0/");
        assert_eq!(info.start_height, 100);
        assert_eq!(info.addr, label_addr());
    }

    #[tokio::test]
    async fn socks5_handshake_completes_ipv4_and_rejects_auth() {
        let (mut ours_io, theirs_io) = duplex(1 << 16);
        let dest: SocketAddr = "10.1.2.3:8333".parse().unwrap();
        let client = async {
            socks5_handshake(&mut ours_io, dest).await.unwrap();
        };
        let server = async move {
            let (mut rd, mut wr) = split(theirs_io);
            let mut greeting = [0u8; 3];
            rd.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            wr.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0u8; 10];
            rd.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0x05, 0x01, 0x00, 0x01, 10, 1, 2, 3, 0x20, 0x8d]);
            wr.write_all(&[0x05, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0, 0]).await.unwrap();
        };
        tokio::join!(client, server);

        // A proxy demanding credentials must be rejected, not silently used.
        let (mut ours_io, theirs_io) = duplex(1 << 16);
        let client = async { socks5_handshake(&mut ours_io, dest).await };
        let server = async move {
            let (mut rd, mut wr) = split(theirs_io);
            let mut greeting = [0u8; 3];
            rd.read_exact(&mut greeting).await.unwrap();
            wr.write_all(&[0x05, 0x02]).await.unwrap();
        };
        let (result, ()) = tokio::join!(client, server);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_rejects_self_connection() {
        let chain = ChainParams::regtest();
        let magic = chain.magic;
        let (ours_io, theirs_io) = duplex(1 << 16);
        let mut peer = Peer::from_stream(ours_io, label_addr(), &chain);

        let remote = async move {
            let (mut rd, mut wr) = split(theirs_io);
            let NetworkMessage::Version(ours) = read_frame(&mut rd, magic).await.unwrap() else {
                panic!("expected version first");
            };
            // Echo our own nonce back, as a connection to ourselves would.
            write_frame(&mut wr, magic, &remote_version(ours.nonce))
                .await
                .unwrap();
        };

        let local = LocalVersion::default();
        let (result, ()) = tokio::join!(peer.handshake(&local), remote);
        assert!(matches!(result, Err(PeerError::SelfConnection)));
    }

    #[tokio::test]
    async fn run_answers_ping_and_forwards_other_messages() {
        let chain = ChainParams::regtest();
        let magic = chain.magic;
        let (ours_io, theirs_io) = duplex(1 << 16);
        let peer = Peer::from_stream(ours_io, label_addr(), &chain);

        let (out_tx, out_rx) = mpsc::channel(8);
        let (events_tx, mut events_rx) = mpsc::channel(8);

        let remote = async move {
            let (mut rd, mut wr) = split(theirs_io);
            write_frame(&mut wr, magic, &NetworkMessage::Ping(9))
                .await
                .unwrap();
            assert_eq!(
                read_frame(&mut rd, magic).await.unwrap(),
                NetworkMessage::Pong(9)
            );
            write_frame(&mut wr, magic, &NetworkMessage::Inv(vec![1, 2, 3]))
                .await
                .unwrap();
            assert_eq!(
                events_rx.recv().await,
                Some(NetworkMessage::Inv(vec![1, 2, 3]))
            );
            // Closing the outbound queue makes run() return Ok.
            drop(out_tx);
            // Hand the halves back so the stream stays open until run() returns.
            // Dropping them here would let run() see EOF and race the clean exit.
            (rd, wr)
        };

        let (result, _halves) = tokio::join!(peer.run(out_rx, events_tx), remote);
        assert!(result.is_ok(), "run returned {result:?}");
    }
}
