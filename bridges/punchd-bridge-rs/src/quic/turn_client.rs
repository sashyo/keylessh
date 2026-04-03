///! TURN client implementation for QUIC UDP relay (RFC 5766).
///!
///! When STUN hole-punching fails (symmetric NAT), QUIC packets are relayed
///! through the TURN server. The TURN server allocates a relay address and
///! forwards UDP packets between client and gateway.
///!
///! Uses TURN ChannelData for minimal overhead (4-byte header vs 36-byte Send Indication).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

type HmacSha1 = Hmac<Sha1>;

// TURN message types
const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;
const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const CHANNEL_BIND_REQUEST: u16 = 0x0009;
const CHANNEL_BIND_SUCCESS: u16 = 0x0109;
const REFRESH_REQUEST: u16 = 0x0004;

// TURN attributes
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_ERROR_CODE: u16 = 0x0009;

const STUN_MAGIC: u32 = 0x2112A442;
const CHANNEL_DATA_MIN: u16 = 0x4000;

/// TURN allocation state.
pub struct TurnAllocation {
    socket: Arc<UdpSocket>,
    turn_addr: SocketAddr,
    relay_addr: SocketAddr,
    channel_number: u16,
    peer_addr: SocketAddr,
    username: String,
    key: Vec<u8>,
    realm: String,
    nonce: String,
}

/// Generate TURN REST API credentials (HMAC-SHA1).
pub fn generate_credentials(secret: &str, username_base: &str) -> (String, String) {
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600;
    let username = format!("{expiry}:{username_base}");
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(username.as_bytes());
    let credential = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, mac.finalize().into_bytes());
    (username, credential)
}

/// Compute credential key for TURN authentication.
/// For REST API credentials (ephemeral): the credential IS the HMAC-SHA1 password,
/// so the key is MD5(username:realm:credential) per RFC 5389 long-term auth.
fn compute_key(username: &str, realm: &str, credential: &str) -> Vec<u8> {
    let digest = md5::compute(format!("{username}:{realm}:{credential}").as_bytes());
    digest.0.to_vec()
}

/// Create a TURN allocation and bind a channel for the given peer.
/// Returns a TurnAllocation that can wrap/unwrap QUIC packets.
pub async fn allocate(
    socket: Arc<UdpSocket>,
    turn_server: &str,
    username: &str,
    credential: &str,
    peer_addr: SocketAddr,
) -> Result<TurnAllocation, String> {
    // Resolve TURN server address
    let turn_str = turn_server
        .trim_start_matches("turn:")
        .trim_start_matches("//");
    let turn_addr: SocketAddr = tokio::net::lookup_host(turn_str).await
        .map_err(|e| format!("TURN DNS resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "TURN server not found".to_string())?;

    tracing::info!("[TURN] Allocating relay via {turn_addr}...");

    // Step 1: Send Allocate request (will get 401 with realm+nonce)
    let txn_id = random_txn_id();
    let mut req = build_stun_header(ALLOCATE_REQUEST, &txn_id, 0);
    // Add REQUESTED-TRANSPORT: UDP (17)
    append_attr(&mut req, ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    update_length(&mut req);

    socket.send_to(&req, turn_addr).await
        .map_err(|e| format!("TURN send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    let n = recv_timeout(&socket, &mut buf, 5).await?;

    // Parse 401 error to get realm and nonce
    let (msg_type, attrs) = parse_stun_response(&buf[..n])?;
    if msg_type != ALLOCATE_ERROR {
        return Err(format!("Expected 401, got msg type 0x{msg_type:04x}"));
    }

    let realm = get_string_attr(&attrs, ATTR_REALM)
        .ok_or_else(|| "No realm in 401".to_string())?;
    let nonce = get_string_attr(&attrs, ATTR_NONCE)
        .ok_or_else(|| "No nonce in 401".to_string())?;

    tracing::debug!("[TURN] Got realm={realm}, nonce={}", &nonce[..16.min(nonce.len())]);

    // Compute key
    let key = compute_key(username, &realm, credential);

    // Step 2: Authenticated Allocate request
    let txn_id = random_txn_id();
    let mut req = build_stun_header(ALLOCATE_REQUEST, &txn_id, 0);
    append_attr(&mut req, ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    append_string_attr(&mut req, ATTR_USERNAME, username);
    append_string_attr(&mut req, ATTR_REALM, &realm);
    append_string_attr(&mut req, ATTR_NONCE, &nonce);
    update_length(&mut req);
    append_message_integrity(&mut req, &key);
    update_length(&mut req);

    socket.send_to(&req, turn_addr).await
        .map_err(|e| format!("TURN send failed: {e}"))?;

    let n = recv_timeout(&socket, &mut buf, 5).await?;
    let (msg_type, attrs) = parse_stun_response(&buf[..n])?;

    if msg_type != ALLOCATE_SUCCESS {
        let error = get_error_code(&attrs).unwrap_or_default();
        return Err(format!("TURN Allocate failed: {error}"));
    }

    let relay_addr = get_xor_address(&attrs, ATTR_XOR_RELAYED_ADDRESS, &buf[4..8])
        .ok_or_else(|| "No relay address in response".to_string())?;

    tracing::info!("[TURN] Relay allocated: {relay_addr}");

    // Step 3: CreatePermission for the peer
    let txn_id = random_txn_id();
    let mut req = build_stun_header(CREATE_PERMISSION_REQUEST, &txn_id, 0);
    append_xor_address(&mut req, ATTR_XOR_PEER_ADDRESS, peer_addr, &txn_id);
    append_string_attr(&mut req, ATTR_USERNAME, username);
    append_string_attr(&mut req, ATTR_REALM, &realm);
    append_string_attr(&mut req, ATTR_NONCE, &nonce);
    update_length(&mut req);
    append_message_integrity(&mut req, &key);
    update_length(&mut req);

    socket.send_to(&req, turn_addr).await
        .map_err(|e| format!("TURN send failed: {e}"))?;

    let n = recv_timeout(&socket, &mut buf, 5).await?;
    let (msg_type, _) = parse_stun_response(&buf[..n])?;
    if msg_type != CREATE_PERMISSION_SUCCESS {
        return Err("TURN CreatePermission failed".to_string());
    }

    tracing::debug!("[TURN] Permission created for {peer_addr}");

    // Step 4: ChannelBind for minimal overhead
    let channel_number: u16 = CHANNEL_DATA_MIN; // 0x4000
    let txn_id = random_txn_id();
    let mut req = build_stun_header(CHANNEL_BIND_REQUEST, &txn_id, 0);
    append_attr(&mut req, ATTR_CHANNEL_NUMBER, &[(channel_number >> 8) as u8, (channel_number & 0xff) as u8, 0, 0]);
    append_xor_address(&mut req, ATTR_XOR_PEER_ADDRESS, peer_addr, &txn_id);
    append_string_attr(&mut req, ATTR_USERNAME, username);
    append_string_attr(&mut req, ATTR_REALM, &realm);
    append_string_attr(&mut req, ATTR_NONCE, &nonce);
    update_length(&mut req);
    append_message_integrity(&mut req, &key);
    update_length(&mut req);

    socket.send_to(&req, turn_addr).await
        .map_err(|e| format!("TURN send failed: {e}"))?;

    let n = recv_timeout(&socket, &mut buf, 5).await?;
    let (msg_type, _) = parse_stun_response(&buf[..n])?;
    if msg_type != CHANNEL_BIND_SUCCESS {
        return Err("TURN ChannelBind failed".to_string());
    }

    tracing::info!("[TURN] Channel 0x{channel_number:04x} bound to {peer_addr}");

    Ok(TurnAllocation {
        socket,
        turn_addr,
        relay_addr,
        channel_number,
        peer_addr,
        username: username.to_string(),
        key,
        realm,
        nonce,
    })
}

impl TurnAllocation {
    /// Get the relay address (public address on the TURN server).
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Wrap a QUIC packet in a TURN ChannelData frame and send it.
    /// ChannelData: [channel:u16][length:u16][data...]
    pub async fn send(&self, data: &[u8]) -> Result<(), String> {
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.push((self.channel_number >> 8) as u8);
        frame.push((self.channel_number & 0xff) as u8);
        frame.push((data.len() >> 8) as u8);
        frame.push((data.len() & 0xff) as u8);
        frame.extend_from_slice(data);
        // Pad to 4-byte boundary
        while frame.len() % 4 != 0 { frame.push(0); }

        self.socket.send_to(&frame, self.turn_addr).await
            .map_err(|e| format!("TURN send: {e}"))?;
        Ok(())
    }

    /// Receive and unwrap a TURN ChannelData frame.
    /// Returns the inner QUIC packet data.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut frame_buf = vec![0u8; 4 + buf.len()];
        let n = self.socket.recv(&mut frame_buf).await
            .map_err(|e| format!("TURN recv: {e}"))?;

        if n < 4 { return Err("Short TURN frame".into()); }

        let channel = u16::from_be_bytes([frame_buf[0], frame_buf[1]]);
        let length = u16::from_be_bytes([frame_buf[2], frame_buf[3]]) as usize;

        if channel >= CHANNEL_DATA_MIN && length <= n - 4 {
            // ChannelData — unwrap
            buf[..length].copy_from_slice(&frame_buf[4..4+length]);
            Ok(length)
        } else {
            // STUN message (not ChannelData) �� skip
            Err("Not a ChannelData frame".into())
        }
    }
}

// ── STUN/TURN message helpers ────────────────────────────────────

fn random_txn_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    for b in &mut id { *b = rand::random::<u8>(); }
    id
}

fn build_stun_header(msg_type: u16, txn_id: &[u8; 12], length: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&msg_type.to_be_bytes());
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    buf.extend_from_slice(txn_id);
    buf
}

fn update_length(buf: &mut Vec<u8>) {
    let len = (buf.len() - 20) as u16;
    buf[2] = (len >> 8) as u8;
    buf[3] = (len & 0xff) as u8;
}

fn append_attr(buf: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    // Pad to 4-byte boundary
    while buf.len() % 4 != 0 { buf.push(0); }
}

fn append_string_attr(buf: &mut Vec<u8>, attr_type: u16, value: &str) {
    append_attr(buf, attr_type, value.as_bytes());
}

fn append_xor_address(buf: &mut Vec<u8>, attr_type: u16, addr: SocketAddr, txn_id: &[u8; 12]) {
    let magic = STUN_MAGIC.to_be_bytes();
    match addr {
        SocketAddr::V4(v4) => {
            let port = v4.port() ^ (STUN_MAGIC >> 16) as u16;
            let ip = v4.ip().octets();
            let xored = [ip[0] ^ magic[0], ip[1] ^ magic[1], ip[2] ^ magic[2], ip[3] ^ magic[3]];
            let mut value = vec![0, 1]; // family = IPv4
            value.extend_from_slice(&port.to_be_bytes());
            value.extend_from_slice(&xored);
            append_attr(buf, attr_type, &value);
        }
        _ => {} // IPv6 not implemented
    }
}

fn append_message_integrity(buf: &mut Vec<u8>, key: &[u8]) {
    // Update length to include MESSAGE-INTEGRITY (24 bytes: 4 header + 20 HMAC)
    let integrity_len = (buf.len() - 20 + 24) as u16;
    buf[2] = (integrity_len >> 8) as u8;
    buf[3] = (integrity_len & 0xff) as u8;

    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key");
    mac.update(buf);
    let result = mac.finalize().into_bytes();

    append_attr(buf, ATTR_MESSAGE_INTEGRITY, &result);
}

fn parse_stun_response(buf: &[u8]) -> Result<(u16, Vec<(u16, Vec<u8>)>), String> {
    if buf.len() < 20 { return Err("Short STUN response".into()); }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut attrs = Vec::new();
    let mut offset = 20;

    while offset + 4 <= 20 + msg_len && offset + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset+1]]);
        let attr_len = u16::from_be_bytes([buf[offset+2], buf[offset+3]]) as usize;
        offset += 4;
        if offset + attr_len > buf.len() { break; }
        attrs.push((attr_type, buf[offset..offset+attr_len].to_vec()));
        offset += (attr_len + 3) & !3; // pad to 4
    }

    Ok((msg_type, attrs))
}

fn get_string_attr(attrs: &[(u16, Vec<u8>)], attr_type: u16) -> Option<String> {
    attrs.iter()
        .find(|(t, _)| *t == attr_type)
        .and_then(|(_, v)| String::from_utf8(v.clone()).ok())
}

fn get_xor_address(attrs: &[(u16, Vec<u8>)], attr_type: u16, magic_bytes: &[u8]) -> Option<SocketAddr> {
    let (_, value) = attrs.iter().find(|(t, _)| *t == attr_type)?;
    if value.len() < 8 { return None; }
    let magic = STUN_MAGIC.to_be_bytes();
    let family = value[1];
    if family == 1 {
        // IPv4
        let port = u16::from_be_bytes([value[2], value[3]]) ^ (STUN_MAGIC >> 16) as u16;
        let ip = std::net::Ipv4Addr::new(
            value[4] ^ magic[0], value[5] ^ magic[1],
            value[6] ^ magic[2], value[7] ^ magic[3],
        );
        Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
    } else {
        None
    }
}

fn get_error_code(attrs: &[(u16, Vec<u8>)]) -> Option<String> {
    let (_, value) = attrs.iter().find(|(t, _)| *t == ATTR_ERROR_CODE)?;
    if value.len() < 4 { return None; }
    let class = value[2] as u16;
    let number = value[3] as u16;
    let code = class * 100 + number;
    let reason = if value.len() > 4 {
        String::from_utf8_lossy(&value[4..]).to_string()
    } else {
        String::new()
    };
    Some(format!("{code} {reason}"))
}

async fn recv_timeout(socket: &UdpSocket, buf: &mut [u8], secs: u64) -> Result<usize, String> {
    tokio::time::timeout(Duration::from_secs(secs), socket.recv(buf))
        .await
        .map_err(|_| "TURN timeout".to_string())?
        .map_err(|e| format!("TURN recv: {e}"))
}
