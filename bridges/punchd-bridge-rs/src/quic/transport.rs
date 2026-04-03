///! QUIC transport layer for punchd gateway.
///!
///! After STUN hole-punching resolves both sides' addresses, the client
///! opens a QUIC connection directly to the gateway. The first stream
///! carries an auth token (JWT). Subsequent streams carry RDP, HTTP,
///! SSH, or VPN traffic.
///!
///! Uses a self-signed certificate — auth is via JWT, not certificate chain.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc;

/// Generate a self-signed certificate for QUIC transport.
/// Auth is via JWT, not TLS certificate — this is just for encryption.
/// Returns (certs, key, sha256_hash_hex)
pub fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["punchd-gateway".to_string()])
        .expect("Failed to generate self-signed cert");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    // Compute SHA-256 hash for WebTransport serverCertificateHashes
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(cert_der.as_ref());
    let hash_hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();

    (vec![cert_der], key_der, hash_hex)
}

/// Create a QUIC server config with the self-signed cert.
/// Returns (ServerConfig, cert_hash_hex).
pub fn make_server_config() -> (ServerConfig, String) {
    let (certs, key, cert_hash) = generate_self_signed_cert();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to create TLS config");

    tls_config.alpn_protocols = vec![b"punchd".to_vec()];

    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    // Allow large streams for RDP/VPN
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    // QUIC datagrams for VPN packets (unreliable)
    transport.datagram_receive_buffer_size(Some(65536));

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .expect("Failed to create QUIC server config"),
    ));
    server_config.transport_config(Arc::new(transport));

    (server_config, cert_hash)
}

/// Create a QUIC client config (skip cert verification — auth is via JWT).
pub fn make_client_config() -> quinn::ClientConfig {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"punchd".to_vec()];

    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    transport.datagram_receive_buffer_size(Some(65536));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .expect("Failed to create QUIC client config"),
    ));
    client_config.transport_config(Arc::new(transport));

    client_config
}

/// Create a QUIC endpoint bound to the given address.
/// Used by the gateway after STUN resolution to accept connections.
/// Returns (Endpoint, cert_hash_hex).
pub fn create_server_endpoint(bind_addr: SocketAddr) -> Result<(Endpoint, String), String> {
    let (server_config, cert_hash) = make_server_config();
    let endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|e| format!("QUIC server bind failed: {e}"))?;
    tracing::info!("[QUIC] Server endpoint listening on {bind_addr}");
    Ok((endpoint, cert_hash))
}

/// Create a QUIC client endpoint (ephemeral port).
pub fn create_client_endpoint() -> Result<Endpoint, String> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| format!("QUIC client bind failed: {e}"))?;
    endpoint.set_default_client_config(make_client_config());
    Ok(endpoint)
}

/// Skip TLS certificate verification — we authenticate via JWT, not certs.
#[derive(Debug)]
struct SkipCertVerification;

impl rustls::client::danger::ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Perform a STUN binding request to discover our public (reflexive) address.
/// Sends a STUN Binding Request from the given UDP socket and returns the
/// XOR-MAPPED-ADDRESS from the response.
pub async fn stun_resolve(
    socket: &tokio::net::UdpSocket,
    stun_server: &str,
) -> Result<SocketAddr, String> {
    use tokio::net::lookup_host;

    // Resolve STUN server address (strip stun: prefix if present)
    let server_addr = stun_server
        .trim_start_matches("stun:")
        .trim_start_matches("//");

    let addr = lookup_host(server_addr).await
        .map_err(|e| format!("STUN DNS resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "STUN server not found".to_string())?;

    // STUN Binding Request (RFC 5389)
    // Header: type=0x0001 (Binding), length=0, magic=0x2112A442, transaction_id=random
    let mut request = [0u8; 20];
    request[0] = 0x00; request[1] = 0x01; // Binding Request
    request[2] = 0x00; request[3] = 0x00; // Length = 0
    request[4] = 0x21; request[5] = 0x12; request[6] = 0xA4; request[7] = 0x42; // Magic Cookie
    // Transaction ID (12 random bytes)
    for i in 8..20 {
        request[i] = rand::random::<u8>();
    }

    socket.send_to(&request, addr).await
        .map_err(|e| format!("STUN send failed: {e}"))?;

    // Read response with timeout
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv(&mut buf),
    ).await
        .map_err(|_| "STUN timeout".to_string())?
        .map_err(|e| format!("STUN recv failed: {e}"))?;

    if n < 20 {
        return Err("STUN response too short".to_string());
    }

    // Verify it's a Binding Success Response (0x0101)
    if buf[0] != 0x01 || buf[1] != 0x01 {
        return Err(format!("STUN unexpected response type: 0x{:02x}{:02x}", buf[0], buf[1]));
    }

    // Parse attributes — look for XOR-MAPPED-ADDRESS (0x0020)
    let magic = [0x21, 0x12, 0xA4, 0x42];
    let mut offset = 20;
    while offset + 4 <= n {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if attr_type == 0x0020 && attr_len >= 8 {
            // XOR-MAPPED-ADDRESS
            let family = buf[offset + 1];
            if family == 0x01 {
                // IPv4
                let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) ^ 0x2112;
                let ip = std::net::Ipv4Addr::new(
                    buf[offset + 4] ^ magic[0],
                    buf[offset + 5] ^ magic[1],
                    buf[offset + 6] ^ magic[2],
                    buf[offset + 7] ^ magic[3],
                );
                return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
            }
        }

        // Align to 4-byte boundary
        offset += (attr_len + 3) & !3;
    }

    Err("No XOR-MAPPED-ADDRESS in STUN response".to_string())
}

/// Stream types multiplexed over QUIC.
/// The first byte of each bidi stream identifies its purpose.
pub mod stream_type {
    /// Auth stream — first stream opened, carries JWT token
    pub const AUTH: u8 = 0x01;
    /// HTTP request/response tunnel (replaces HTTP relay)
    pub const HTTP: u8 = 0x02;
    /// WebSocket tunnel (RDCleanPath, tcp-forward)
    pub const WEBSOCKET: u8 = 0x03;
    /// VPN IP packets (uses QUIC datagrams, not streams)
    pub const VPN: u8 = 0x04;
    /// SSH terminal session
    pub const SSH: u8 = 0x05;
}
