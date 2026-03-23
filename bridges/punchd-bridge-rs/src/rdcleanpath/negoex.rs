// NEGOEX binary message codec (MS-NEGOEX).
//
// NEGOEX extends SPNEGO by allowing custom authentication schemes.
// Messages are binary (NOT ASN.1), carried inside SPNEGO mechTokens.
// All multi-byte integers are little-endian.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

// ── Constants ────────────────────────────────────────────────────

const NEGOEX_SIGNATURE: &[u8; 8] = b"NEGOEXTS";

pub const MSG_INITIATOR_NEGO: u32 = 0;
pub const MSG_ACCEPTOR_NEGO: u32 = 1;
#[allow(dead_code)]
pub const MSG_INITIATOR_META_DATA: u32 = 2;
#[allow(dead_code)]
pub const MSG_ACCEPTOR_META_DATA: u32 = 3;
pub const MSG_CHALLENGE: u32 = 4;
pub const MSG_AP_REQUEST: u32 = 5;
pub const MSG_VERIFY: u32 = 6;
#[allow(dead_code)]
pub const MSG_ALERT: u32 = 7;

/// NEGOEX OID: 1.3.6.1.4.1.311.2.2.30
pub const NEGOEX_OID: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e,
];

/// TideSSP AuthScheme GUID: {7A4E8B2C-1F3D-4A5E-9C6B-8D7E0F1A2B3C}
/// Mixed-endian (Microsoft) format.
pub const TIDESSP_AUTH_SCHEME: &[u8; 16] = &[
    0x2c, 0x8b, 0x4e, 0x7a, // Data1 LE
    0x3d, 0x1f,             // Data2 LE
    0x5e, 0x4a,             // Data3 LE
    0x9c, 0x6b,             // Data4[0..1] BE
    0x8d, 0x7e, 0x0f, 0x1a, 0x2b, 0x3c, // Data4[2..7] BE
];

const CHECKSUM_SCHEME_RFC3961: u32 = 1;
pub const CHECKSUM_TYPE_HMAC_SHA1_96_AES128: i32 = 15;

const HEADER_SIZE: usize = 40;

pub const TOKEN_JWT: u8 = 0x04;

// ── Types ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct NegoexMessage {
    pub message_type: u32,
    pub sequence_num: u32,
    pub conversation_id: [u8; 16],
    pub auth_schemes: Vec<[u8; 16]>,
    pub auth_scheme: Option<[u8; 16]>,
    pub exchange: Option<Vec<u8>>,
    pub checksum: Option<Vec<u8>>,
    pub checksum_type: Option<i32>,
}

// ── Builders ─────────────────────────────────────────────────────

fn write_header(buf: &mut [u8], msg_type: u32, seq_num: u32, header_len: u32, total_len: u32, conversation_id: &[u8; 16]) {
    buf[0..8].copy_from_slice(NEGOEX_SIGNATURE);
    buf[8..12].copy_from_slice(&msg_type.to_le_bytes());
    buf[12..16].copy_from_slice(&seq_num.to_le_bytes());
    buf[16..20].copy_from_slice(&header_len.to_le_bytes());
    buf[20..24].copy_from_slice(&total_len.to_le_bytes());
    buf[24..40].copy_from_slice(conversation_id);
}

/// Build NEGOEX NEGO_MESSAGE (initiator or acceptor).
pub fn build_nego_message(msg_type: u32, conversation_id: &[u8; 16], seq_num: u32, auth_schemes: &[[u8; 16]]) -> Vec<u8> {
    let header_len: u32 = 96;
    let schemes_size = auth_schemes.len() as u32 * 16;
    let total_len = header_len + schemes_size;
    let mut buf = vec![0u8; total_len as usize];

    write_header(&mut buf, msg_type, seq_num, header_len, total_len, conversation_id);

    // Random[32] at offset 40
    let random: [u8; 32] = rand::random();
    buf[40..72].copy_from_slice(&random);

    // ProtocolVersion = 0 (u64 LE) at offset 72
    buf[72..80].copy_from_slice(&0u64.to_le_bytes());

    // AuthSchemes vector
    buf[80..84].copy_from_slice(&header_len.to_le_bytes()); // offset
    buf[84..86].copy_from_slice(&(auth_schemes.len() as u16).to_le_bytes()); // count
    // padding at 86-87 already 0

    // Extensions vector (empty) at 88-95 already 0

    // Write auth scheme GUIDs
    let mut off = header_len as usize;
    for scheme in auth_schemes {
        buf[off..off + 16].copy_from_slice(scheme);
        off += 16;
    }

    buf
}

/// Build NEGOEX EXCHANGE_MESSAGE (AP_REQUEST, CHALLENGE, META_DATA).
pub fn build_exchange_message(msg_type: u32, conversation_id: &[u8; 16], seq_num: u32, auth_scheme: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let header_len: u32 = 64;
    let total_len = header_len + payload.len() as u32;
    let mut buf = vec![0u8; total_len as usize];

    write_header(&mut buf, msg_type, seq_num, header_len, total_len, conversation_id);

    // AuthScheme GUID at offset 40
    buf[40..56].copy_from_slice(auth_scheme);

    // Exchange vector
    buf[56..60].copy_from_slice(&header_len.to_le_bytes()); // offset
    buf[60..64].copy_from_slice(&(payload.len() as u32).to_le_bytes()); // length

    // Payload
    buf[64..64 + payload.len()].copy_from_slice(payload);

    buf
}

/// Build NEGOEX VERIFY_MESSAGE.
pub fn build_verify_message(conversation_id: &[u8; 16], seq_num: u32, auth_scheme: &[u8; 16], checksum_value: &[u8], checksum_type: i32) -> Vec<u8> {
    let header_len: u32 = 80;
    let total_len = header_len + checksum_value.len() as u32;
    let mut buf = vec![0u8; total_len as usize];

    write_header(&mut buf, MSG_VERIFY, seq_num, header_len, total_len, conversation_id);

    buf[40..56].copy_from_slice(auth_scheme);

    // Checksum structure
    buf[56..60].copy_from_slice(&20u32.to_le_bytes()); // cbHeaderLength
    buf[60..64].copy_from_slice(&CHECKSUM_SCHEME_RFC3961.to_le_bytes());
    buf[64..68].copy_from_slice(&checksum_type.to_le_bytes());
    buf[68..72].copy_from_slice(&header_len.to_le_bytes()); // value offset
    buf[72..76].copy_from_slice(&(checksum_value.len() as u32).to_le_bytes());
    // bytes 76-79: zero padding

    buf[80..80 + checksum_value.len()].copy_from_slice(checksum_value);

    buf
}

// ── Parser ──────────────────────────────────────────────────────

pub fn parse_negoex_messages(data: &[u8]) -> Result<Vec<NegoexMessage>, String> {
    let mut messages = Vec::new();
    let mut pos = 0;

    while pos + HEADER_SIZE <= data.len() {
        if &data[pos..pos + 8] != NEGOEX_SIGNATURE {
            return Err(format!("NEGOEX: invalid signature at offset {pos}"));
        }

        let message_type = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        let sequence_num = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap());
        let msg_len = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap()) as usize;
        let mut conversation_id = [0u8; 16];
        conversation_id.copy_from_slice(&data[pos + 24..pos + 40]);

        if pos + msg_len > data.len() {
            return Err("NEGOEX: message overflows buffer".into());
        }

        let mut msg = NegoexMessage {
            message_type,
            sequence_num,
            conversation_id,
            auth_schemes: Vec::new(),
            auth_scheme: None,
            exchange: None,
            checksum: None,
            checksum_type: None,
        };

        if (message_type == MSG_INITIATOR_NEGO || message_type == MSG_ACCEPTOR_NEGO) && msg_len >= 96 {
            let schemes_offset = u32::from_le_bytes(data[pos + 80..pos + 84].try_into().unwrap()) as usize;
            let schemes_count = u16::from_le_bytes(data[pos + 84..pos + 86].try_into().unwrap()) as usize;
            for i in 0..schemes_count {
                let sp = pos + schemes_offset + i * 16;
                if sp + 16 <= pos + msg_len {
                    let mut guid = [0u8; 16];
                    guid.copy_from_slice(&data[sp..sp + 16]);
                    msg.auth_schemes.push(guid);
                }
            }
        } else if matches!(message_type, MSG_CHALLENGE | MSG_AP_REQUEST | 2 | 3) && msg_len >= 64 {
            let mut auth_scheme = [0u8; 16];
            auth_scheme.copy_from_slice(&data[pos + 40..pos + 56]);
            msg.auth_scheme = Some(auth_scheme);
            let ex_offset = u32::from_le_bytes(data[pos + 56..pos + 60].try_into().unwrap()) as usize;
            let ex_length = u32::from_le_bytes(data[pos + 60..pos + 64].try_into().unwrap()) as usize;
            if ex_offset + ex_length <= msg_len {
                msg.exchange = Some(data[pos + ex_offset..pos + ex_offset + ex_length].to_vec());
            }
        } else if message_type == MSG_VERIFY && msg_len >= 76 {
            let mut auth_scheme = [0u8; 16];
            auth_scheme.copy_from_slice(&data[pos + 40..pos + 56]);
            msg.auth_scheme = Some(auth_scheme);
            msg.checksum_type = Some(i32::from_le_bytes(data[pos + 64..pos + 68].try_into().unwrap()));
            let ck_offset = u32::from_le_bytes(data[pos + 68..pos + 72].try_into().unwrap()) as usize;
            let ck_length = u32::from_le_bytes(data[pos + 72..pos + 76].try_into().unwrap()) as usize;
            if ck_offset + ck_length <= msg_len {
                msg.checksum = Some(data[pos + ck_offset..pos + ck_offset + ck_length].to_vec());
            }
        }

        messages.push(msg);
        pos += msg_len;
    }

    Ok(messages)
}

// ── Session Key & Checksum ───────────────────────────────────────

/// Derive the NEGOEX session key from JWT signature bytes.
/// sessionKey = SHA-256(jwt_signature_bytes)[0..16]
pub fn derive_session_key_from_jwt(jwt: &str) -> [u8; 16] {
    let last_dot = jwt.rfind('.').expect("Invalid JWT");
    let sig_b64 = &jwt[last_dot + 1..];
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .unwrap_or_default();

    let hash = Sha256::digest(&sig_bytes);
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    key
}

use base64::Engine;

// ── RFC 3961 n-fold ──────────────────────────────────────────────

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

fn nfold(input: &[u8], out_bits: usize) -> Vec<u8> {
    let in_len = input.len();
    let in_bits = in_len * 8;
    let out_len = out_bits / 8;
    let lcm_bytes = (in_len * out_len) / gcd(in_len, out_len);

    let mut out = vec![0u8; out_len];
    let mut carry: u32 = 0;

    for i in (0..lcm_bytes).rev() {
        let copy = i / in_len;
        let offset = i % in_len;
        let rotation = (13 * copy) % in_bits;

        let src_start = (((offset * 8) as isize - rotation as isize).rem_euclid(in_bits as isize)) as usize;
        let src_byte = src_start / 8;
        let src_bit = src_start % 8;

        let b1 = input[src_byte % in_len];
        let b2 = input[(src_byte + 1) % in_len];
        let val = if src_bit == 0 {
            b1
        } else {
            ((b1 << src_bit) | (b2 >> (8 - src_bit))) & 0xff
        };

        carry += val as u32 + out[i % out_len] as u32;
        out[i % out_len] = (carry & 0xff) as u8;
        carry >>= 8;
    }

    if carry > 0 {
        for i in (0..out_len).rev() {
            carry += out[i] as u32;
            out[i] = (carry & 0xff) as u8;
            carry >>= 8;
        }
    }

    out
}

/// RFC 3961 DK(base_key, constant) for AES-128.
fn dk(base_key: &[u8; 16], constant: &[u8]) -> [u8; 16] {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;

    let folded = nfold(constant, 128);
    let cipher = Aes128::new(base_key.into());
    let mut block = aes::Block::from_slice(&folded).clone();
    cipher.encrypt_block(&mut block);
    let mut key = [0u8; 16];
    key.copy_from_slice(&block);
    key
}

/// Compute hmac-sha1-96-aes128 checksum (RFC 3962, type 15).
/// Kc = DK(base_key, pack_be32(keyUsage) || 0x99)
/// checksum = HMAC-SHA1(Kc, data)[0:12]
pub fn compute_aes128_checksum(session_key: &[u8; 16], key_usage: u32, data: &[u8]) -> Vec<u8> {
    let mut constant = [0u8; 5];
    constant[0..4].copy_from_slice(&key_usage.to_be_bytes());
    constant[4] = 0x99; // Kc

    let kc = dk(session_key, &constant);
    let mut mac = Hmac::<Sha1>::new_from_slice(&kc).unwrap();
    mac.update(data);
    let result = mac.finalize().into_bytes();
    result[..12].to_vec()
}

/// Generate a random NEGOEX conversation ID (GUID).
pub fn generate_conversation_id() -> [u8; 16] {
    rand::random()
}
