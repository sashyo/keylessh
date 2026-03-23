// CredSSP client for TideSSP JWT authentication via NEGOEX.
//
// Performs NLA (Network Level Authentication) with the RDP server using
// NegoExtender (MS-NEGOEX) to carry TideSSP tokens through SPNEGO.
//
// Protocol flow:
// 1. Client → Server: TSRequest { SPNEGO NegTokenInit { NEGOEX[INIT_NEGO + AP_REQUEST(JWT)] } }
// 2. Server → Client: TSRequest { SPNEGO NegTokenResp { NEGOEX[ACCEPT_NEGO + VERIFY] } }
// 3. Client → Server: TSRequest { SPNEGO NegTokenResp { NEGOEX[VERIFY] } }
// 4. Server → Client: TSRequest confirming SPNEGO complete
// 5. Client → Server: TSRequest { pubKeyAuth }
// 6. Server → Client: TSRequest { pubKeyAuth confirmation }
// 7. Client → Server: TSRequest { authInfo (TSCredentials) }

use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;

use super::der_codec::*;
use super::negoex::*;

const CREDSSP_VERSION: i64 = 6;

// SPNEGO OID: 1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

// ── Main entry point ────────────────────────────────────────────

/// Perform CredSSP/NLA authentication over a TLS-wrapped RDP connection.
pub async fn perform_credssp(tls: &mut TlsStream<TcpStream>, jwt: &str) -> Result<(), String> {
    let mut conversation_id = generate_conversation_id();
    let mut seq_num: u32 = 0;
    let mut transcript: Vec<Vec<u8>> = Vec::new();

    // CredSSP v5+ requires clientNonce
    let client_nonce: [u8; 32] = rand::random();
    tracing::info!("[CredSSP] clientNonce: {}", hex::encode(&client_nonce));

    // ── Step 1: Send INITIATOR_NEGO + optimistic AP_REQUEST(JWT) ──

    let nego_msg = build_nego_message(MSG_INITIATOR_NEGO, &conversation_id, seq_num, &[*TIDESSP_AUTH_SCHEME]);
    seq_num += 1;

    // Build JWT token: [0x04][JWT ASCII bytes]
    let mut jwt_token = vec![TOKEN_JWT];
    jwt_token.extend_from_slice(jwt.as_bytes());

    let ap_req_msg = build_exchange_message(MSG_AP_REQUEST, &conversation_id, seq_num, TIDESSP_AUTH_SCHEME, &jwt_token);
    seq_num += 1;

    let mut init_negoex = Vec::new();
    init_negoex.extend_from_slice(&nego_msg);
    init_negoex.extend_from_slice(&ap_req_msg);
    transcript.push(nego_msg);
    transcript.push(ap_req_msg);

    let spnego_init = build_spnego_init(&init_negoex);
    let ts_req1 = build_ts_request(CREDSSP_VERSION, Some(&spnego_init), None, None, Some(&client_nonce));
    tls.write_all(&ts_req1).await.map_err(|e| format!("write step1: {e}"))?;
    tracing::info!("[CredSSP] Sent INITIATOR_NEGO + AP_REQUEST(JWT)");

    // ── Step 2: Read server response ──

    let ts_resp1 = read_ts_request(tls).await?;
    if let Some(ec) = ts_resp1.error_code {
        return Err(format!("CredSSP: server error 0x{ec:08x}"));
    }

    let server_spnego1 = ts_resp1.nego_token.ok_or("CredSSP: no negoToken in server response")?;
    let server_negoex1 = extract_spnego_mech_token(&server_spnego1).ok_or("CredSSP: invalid NEGOEX response")?;
    let server_msgs = parse_negoex_messages(&server_negoex1)?;
    tracing::info!("[CredSSP] Server sent {} NEGOEX message(s)", server_msgs.len());

    // Record non-VERIFY messages in transcript
    {
        let mut pos = 0;
        while pos + 40 <= server_negoex1.len() {
            let msg_len = u32::from_le_bytes(server_negoex1[pos + 20..pos + 24].try_into().unwrap()) as usize;
            let msg_type = u32::from_le_bytes(server_negoex1[pos + 8..pos + 12].try_into().unwrap());
            if msg_type != MSG_VERIFY {
                transcript.push(server_negoex1[pos..pos + msg_len].to_vec());
            }
            pos += msg_len;
        }
    }

    // Use conversation ID from server
    if let Some(first) = server_msgs.first() {
        conversation_id = first.conversation_id;
    }

    // Update seqNum
    for msg in &server_msgs {
        if msg.sequence_num >= seq_num {
            seq_num = msg.sequence_num + 1;
        }
    }

    // Check for VERIFY (JWT accepted) or CHALLENGE (unexpected)
    let server_verify = server_msgs.iter().find(|m| m.message_type == MSG_VERIFY);
    let server_challenge = server_msgs.iter().find(|m| m.message_type == MSG_CHALLENGE);

    if server_challenge.is_some() {
        return Err("CredSSP: server sent CHALLENGE — expected JWT single-round auth".into());
    }

    let session_key = derive_session_key_from_jwt(jwt);
    tracing::info!("[CredSSP] Session key: {}", hex::encode(&session_key));

    let server_verify = server_verify.ok_or("CredSSP: server did not send VERIFY")?;
    if server_verify.checksum.is_none() {
        return Err("CredSSP: server VERIFY has no checksum".into());
    }
    tracing::info!("[CredSSP] Server VERIFY: checksumType={:?}, checksum={}",
        server_verify.checksum_type,
        server_verify.checksum.as_ref().map(|c| hex::encode(c)).unwrap_or_default());

    // ── Step 3: Send client VERIFY ──

    // Extract raw server VERIFY bytes for full transcript
    let server_verify_raw = {
        let mut pos = 0;
        let mut found = None;
        while pos + 40 <= server_negoex1.len() {
            let msg_len = u32::from_le_bytes(server_negoex1[pos + 20..pos + 24].try_into().unwrap()) as usize;
            let msg_type = u32::from_le_bytes(server_negoex1[pos + 8..pos + 12].try_into().unwrap());
            if msg_type == MSG_VERIFY {
                found = Some(server_negoex1[pos..pos + msg_len].to_vec());
            }
            pos += msg_len;
        }
        found.ok_or("CredSSP: could not extract server VERIFY bytes")?
    };

    // Full transcript = all non-VERIFY msgs + server VERIFY
    let transcript_data: Vec<u8> = transcript.iter().flat_map(|v| v.iter().copied()).collect();
    let mut full_transcript = transcript_data.clone();
    full_transcript.extend_from_slice(&server_verify_raw);

    let ku_client_verify: u32 = 25;
    tracing::info!("[CredSSP] Transcript: {} parts, {} bytes total, full_transcript={} bytes",
        transcript.len(), transcript_data.len(), full_transcript.len());
    let client_checksum = compute_aes128_checksum(&session_key, ku_client_verify, &full_transcript);
    tracing::info!("[CredSSP] Client VERIFY checksum (ku={}): {}", ku_client_verify, hex::encode(&client_checksum));

    let client_verify = build_verify_message(&conversation_id, seq_num, TIDESSP_AUTH_SCHEME, &client_checksum, CHECKSUM_TYPE_HMAC_SHA1_96_AES128);
    seq_num += 1;

    let verify_spnego = build_spnego_response(Some(&client_verify), None);
    let ts_req_verify = build_ts_request(CREDSSP_VERSION, Some(&verify_spnego), None, None, Some(&client_nonce));
    tls.write_all(&ts_req_verify).await.map_err(|e| format!("write step3: {e}"))?;
    tracing::info!("[CredSSP] Sent client VERIFY ({} bytes)", client_verify.len());

    // ── Step 4: Read SPNEGO accept-complete ──

    let ts_resp_complete = read_ts_request(tls).await?;
    if let Some(ec) = ts_resp_complete.error_code {
        return Err(format!("CredSSP: server error after VERIFY 0x{ec:08x}"));
    }
    tracing::info!("[CredSSP] SPNEGO/NEGOEX authentication complete");

    // ── Step 5: Send pubKeyAuth (TLS channel binding) ──

    let server_cert_raw = extract_tls_server_cert(tls)?;
    let subject_public_key = extract_subject_public_key_from_cert_der(&server_cert_raw)?;

    let hash_magic = b"CredSSP Client-To-Server Binding Hash\0";
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(hash_magic);
    hash_input.extend_from_slice(&client_nonce);
    hash_input.extend_from_slice(&subject_public_key);

    let client_hash = Sha256::digest(&hash_input);
    let pub_key_auth = tide_gcm_encrypt(&session_key, &client_hash)?;

    let ts_req3 = build_ts_request(CREDSSP_VERSION, None, None, Some(&pub_key_auth), Some(&client_nonce));
    tls.write_all(&ts_req3).await.map_err(|e| format!("write step5: {e}"))?;
    tracing::info!("[CredSSP] Sent pubKeyAuth");

    // ── Step 6: Read pubKeyAuth confirmation ──

    let ts_resp3 = read_ts_request(tls).await?;
    if let Some(ec) = ts_resp3.error_code {
        return Err(format!("CredSSP: server error during pubKeyAuth 0x{ec:08x}"));
    }
    let server_pub_key_auth = ts_resp3.pub_key_auth.ok_or("CredSSP: no pubKeyAuth confirmation")?;

    let server_hash_magic = b"CredSSP Server-To-Client Binding Hash\0";
    let mut server_hash_input = Vec::new();
    server_hash_input.extend_from_slice(server_hash_magic);
    server_hash_input.extend_from_slice(&client_nonce);
    server_hash_input.extend_from_slice(&subject_public_key);
    let expected_server_hash = Sha256::digest(&server_hash_input);

    let decrypted = tide_gcm_decrypt(&session_key, &server_pub_key_auth)?;
    if decrypted != expected_server_hash.as_slice() {
        return Err("CredSSP: server pubKeyAuth hash mismatch".into());
    }
    tracing::info!("[CredSSP] Server pubKeyAuth verified OK");

    // ── Step 7: Send authInfo (TSCredentials) ──

    let jwt_payload = jwt.split('.').nth(1).ok_or("Invalid JWT")?;
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt_payload)
        .map_err(|e| format!("JWT payload decode: {e}"))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).map_err(|e| format!("JWT parse: {e}"))?;
    let username = payload.get("preferred_username")
        .or_else(|| payload.get("sub"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    tracing::info!("[CredSSP] TSCredentials: user=\"{username}\", pass=\"\" (Restricted Admin)");
    let auth_info_plain = build_auth_info(username, "", ".");
    let auth_info_enc = tide_gcm_encrypt(&session_key, &auth_info_plain)?;
    let ts_req4 = build_ts_request(CREDSSP_VERSION, None, Some(&auth_info_enc), None, Some(&client_nonce));
    tls.write_all(&ts_req4).await.map_err(|e| format!("write step7: {e}"))?;

    tracing::info!("[CredSSP] NLA authentication completed successfully");
    Ok(())
}

// ── SPNEGO Builders ─────────────────────────────────────────────

fn build_spnego_init(mech_token: &[u8]) -> Vec<u8> {
    let mech_types = encode_explicit(0, &encode_tlv(TAG_SEQUENCE, NEGOEX_OID));
    let mech_token_wrapped = encode_explicit(2, &encode_octet_string(mech_token));
    let neg_token_init = encode_sequence(&[&mech_types, &mech_token_wrapped]);
    let mut inner = Vec::new();
    inner.extend_from_slice(SPNEGO_OID);
    inner.extend_from_slice(&encode_tlv(0xa0, &neg_token_init));
    encode_tlv(0x60, &inner)
}

fn build_spnego_response(response_token: Option<&[u8]>, _mech_list_mic: Option<&[u8]>) -> Vec<u8> {
    let mut elements: Vec<Vec<u8>> = Vec::new();
    if let Some(token) = response_token {
        elements.push(encode_explicit(2, &encode_octet_string(token)));
    }
    let neg_token_resp = encode_sequence_from_vecs(&elements);
    encode_tlv(0xa1, &neg_token_resp)
}

fn extract_spnego_mech_token(spnego: &[u8]) -> Option<Vec<u8>> {
    // Parse SPNEGO to find responseToken [2] OCTET STRING
    let mut reader = if spnego[0] == 0x60 {
        // NegTokenInit wrapped in APPLICATION [0]
        let mut app_reader = DerReader::new(spnego);
        let (_tag, app_content) = app_reader.read_tlv().ok()?;
        let mut content_reader = DerReader::new(&app_content);
        content_reader.read_tlv().ok()?; // skip OID
        let mut init_wrapper = content_reader.read_explicit(0).ok()??;
        init_wrapper.read_sequence_inner().ok()?
    } else if spnego[0] == 0xa1 {
        // NegTokenResp
        let mut resp_reader = DerReader::new(spnego);
        let (_tag, resp_content) = resp_reader.read_tlv().ok()?;
        DerReader::new(&resp_content).read_sequence_inner().ok()?
    } else {
        DerReader::new(spnego).read_sequence_inner().ok()?
    };

    while reader.has_more() {
        let tag = reader.peek_tag()?;
        if tag == context_tag(2) {
            let mut wrapper = reader.read_explicit(2).ok()??;
            return wrapper.read_octet_string().ok();
        }
        reader.read_tlv().ok()?;
    }
    None
}

// ── TSRequest (MS-CSSP) ─────────────────────────────────────────

fn build_ts_request(version: i64, nego_token: Option<&[u8]>, auth_info: Option<&[u8]>, pub_key_auth: Option<&[u8]>, client_nonce: Option<&[u8]>) -> Vec<u8> {
    let mut elements: Vec<Vec<u8>> = Vec::new();
    elements.push(encode_explicit(0, &encode_integer(version)));

    if let Some(token) = nego_token {
        let token_entry = encode_sequence(&[&encode_explicit(0, &encode_octet_string(token))]);
        elements.push(encode_explicit(1, &encode_sequence(&[&token_entry])));
    }

    if let Some(info) = auth_info {
        elements.push(encode_explicit(2, &encode_octet_string(info)));
    }

    if let Some(pka) = pub_key_auth {
        elements.push(encode_explicit(3, &encode_octet_string(pka)));
    }

    if let Some(nonce) = client_nonce {
        elements.push(encode_explicit(5, &encode_octet_string(nonce)));
    }

    encode_sequence_from_vecs(&elements)
}

struct TsRequestData {
    #[allow(dead_code)]
    version: i64,
    nego_token: Option<Vec<u8>>,
    #[allow(dead_code)]
    auth_info: Option<Vec<u8>>,
    pub_key_auth: Option<Vec<u8>>,
    error_code: Option<i64>,
}

fn parse_ts_request(data: &[u8]) -> Result<TsRequestData, String> {
    let mut reader = DerReader::new(data).read_sequence_inner().map_err(|e| format!("TSRequest parse: {e}"))?;
    let mut result = TsRequestData {
        version: 0,
        nego_token: None,
        auth_info: None,
        pub_key_auth: None,
        error_code: None,
    };

    if let Some(mut vw) = reader.read_explicit(0).ok().flatten() {
        result.version = vw.read_integer_value().unwrap_or(0);
    }

    while reader.has_more() {
        let tag = match reader.peek_tag() {
            Some(t) => t,
            None => break,
        };
        if tag == context_tag(1) {
            if let Some(mut wrapper) = reader.read_explicit(1).ok().flatten() {
                if let Ok(mut seq) = wrapper.read_sequence_inner() {
                    if let Ok(mut entry) = seq.read_sequence_inner() {
                        if let Some(mut tw) = entry.read_explicit(0).ok().flatten() {
                            result.nego_token = tw.read_octet_string().ok();
                        }
                    }
                }
            }
        } else if tag == context_tag(2) {
            if let Some(mut wrapper) = reader.read_explicit(2).ok().flatten() {
                result.auth_info = wrapper.read_octet_string().ok();
            }
        } else if tag == context_tag(3) {
            if let Some(mut wrapper) = reader.read_explicit(3).ok().flatten() {
                result.pub_key_auth = wrapper.read_octet_string().ok();
            }
        } else if tag == context_tag(4) {
            if let Some(mut wrapper) = reader.read_explicit(4).ok().flatten() {
                result.error_code = wrapper.read_integer_value();
            }
        } else if tag == context_tag(5) {
            let _ = reader.read_tlv();
        } else {
            let _ = reader.read_tlv();
        }
    }

    Ok(result)
}

async fn read_ts_request(tls: &mut TlsStream<TcpStream>) -> Result<TsRequestData, String> {
    // Read DER SEQUENCE: tag + length + content
    let mut header = [0u8; 6]; // max header: tag(1) + length(up to 4) + 1 extra
    tls.read_exact(&mut header[..2]).await.map_err(|e| format!("read TSRequest header: {e}"))?;

    if header[0] != 0x30 {
        return Err(format!("Expected SEQUENCE (0x30), got 0x{:02x}", header[0]));
    }

    let (content_len, header_len) = if header[1] < 0x80 {
        (header[1] as usize, 2usize)
    } else {
        let num_bytes = (header[1] & 0x7f) as usize;
        if num_bytes > 4 {
            return Err("DER length too large".into());
        }
        tls.read_exact(&mut header[2..2 + num_bytes]).await.map_err(|e| format!("read len: {e}"))?;
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | header[2 + i] as usize;
        }
        (len, 2 + num_bytes)
    };

    let mut full = vec![0u8; header_len + content_len];
    full[..header_len].copy_from_slice(&header[..header_len]);

    tokio::time::timeout(
        Duration::from_secs(10),
        tls.read_exact(&mut full[header_len..]),
    )
    .await
    .map_err(|_| "TSRequest read timeout".to_string())?
    .map_err(|e| format!("read TSRequest content: {e}"))?;

    parse_ts_request(&full)
}

// ── TLS Certificate ─────────────────────────────────────────────

fn extract_tls_server_cert(tls: &TlsStream<TcpStream>) -> Result<Vec<u8>, String> {
    let inner = tls.get_ref();
    match inner.peer_certificate() {
        Ok(Some(cert)) => cert.to_der().map_err(|e| format!("cert to DER: {e}")),
        _ => Err("Cannot get server TLS certificate".into()),
    }
}

fn extract_subject_public_key_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let mut pos = 0;

    // Outer SEQUENCE
    if cert_der.get(pos) != Some(&0x30) { return Err("expected outer SEQUENCE".into()); }
    pos += 1;
    pos += der_len_bytes(cert_der, pos);

    // TBSCertificate SEQUENCE
    if cert_der.get(pos) != Some(&0x30) { return Err("expected TBS SEQUENCE".into()); }
    pos += 1;
    pos += der_len_bytes(cert_der, pos);

    // Skip version [0] EXPLICIT if present
    if cert_der.get(pos) == Some(&0xa0) { pos = der_skip_tlv(cert_der, pos); }

    // Skip: serialNumber, signature, issuer, validity, subject (5 fields)
    for _ in 0..5 { pos = der_skip_tlv(cert_der, pos); }

    // SubjectPublicKeyInfo SEQUENCE
    if cert_der.get(pos) != Some(&0x30) { return Err("expected SPKI SEQUENCE".into()); }
    pos += 1;
    pos += der_len_bytes(cert_der, pos);

    // Skip AlgorithmIdentifier
    pos = der_skip_tlv(cert_der, pos);

    // BIT STRING
    if cert_der.get(pos) != Some(&0x03) { return Err("expected BIT STRING".into()); }
    pos += 1;
    let len_size = der_len_bytes(cert_der, pos);
    let bit_string_len = der_read_len(cert_der, pos);
    pos += len_size;

    // Skip unused-bits byte
    pos += 1;
    let key_len = bit_string_len - 1;

    Ok(cert_der[pos..pos + key_len].to_vec())
}

fn der_len_bytes(buf: &[u8], pos: usize) -> usize {
    let first = buf[pos];
    if first < 0x80 { 1 } else { 1 + (first & 0x7f) as usize }
}

fn der_read_len(buf: &[u8], pos: usize) -> usize {
    let first = buf[pos];
    if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | buf[pos + 1 + i] as usize;
        }
        len
    }
}

fn der_skip_tlv(buf: &[u8], mut pos: usize) -> usize {
    pos += 1; // skip tag
    let first = buf[pos];
    if first < 0x80 {
        pos + 1 + first as usize
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | buf[pos + 1 + i] as usize;
        }
        pos + 1 + n + len
    }
}

// ── AES-128-GCM encryption (matches TideSSP SealMessage) ────────
// Wire format: [12-byte nonce] [16-byte GCM tag] [ciphertext]

fn tide_gcm_encrypt(key: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new(key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("GCM encrypt: {e}"))?;

    // ciphertext from aes-gcm includes the tag appended
    // Split: ciphertext = encrypted_data || tag(16)
    let enc_len = ciphertext.len() - 16;
    let mut out = Vec::with_capacity(12 + 16 + enc_len);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext[enc_len..]); // tag
    out.extend_from_slice(&ciphertext[..enc_len]); // encrypted data
    Ok(out)
}

fn tide_gcm_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 28 {
        return Err("GCM data too short".into());
    }
    let nonce_bytes = &data[..12];
    let tag = &data[12..28];
    let ciphertext = &data[28..];

    let cipher = Aes128Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    // aes-gcm expects ciphertext || tag
    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);

    cipher.decrypt(nonce, combined.as_ref())
        .map_err(|e| format!("GCM decrypt: {e}"))
}

// ── Auth Info ───────────────────────────────────────────────────

fn build_auth_info(username: &str, password: &str, domain: &str) -> Vec<u8> {
    let domain_utf16 = to_utf16le(domain);
    let user_utf16 = to_utf16le(username);
    let pass_utf16 = to_utf16le(password);

    let ts_creds = encode_sequence(&[
        &encode_explicit(0, &encode_octet_string(&domain_utf16)),
        &encode_explicit(1, &encode_octet_string(&user_utf16)),
        &encode_explicit(2, &encode_octet_string(&pass_utf16)),
    ]);

    encode_sequence(&[
        &encode_explicit(0, &encode_integer(1)),
        &encode_explicit(1, &encode_octet_string(&ts_creds)),
    ])
}

fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

// ── Hex helper ──────────────────────────────────────────────────

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

use base64::Engine;
