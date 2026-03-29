// RDCleanPath PDU types — port of the TypeScript original.

use super::der_codec::*;

pub const RDCLEANPATH_VERSION: i64 = 3390;
pub const RDCLEANPATH_ERROR_GENERAL: i64 = 1;
#[allow(dead_code)]
pub const RDCLEANPATH_ERROR_NEGOTIATION: i64 = 2;

#[allow(dead_code)]
pub struct RDCleanPathRequest {
    pub version: i64,
    pub destination: String,
    pub proxy_auth: String,
    pub preconnection_blob: Option<String>,
    pub x224_connection_pdu: Vec<u8>,
}

pub struct RDCleanPathResponse {
    pub x224_connection_pdu: Vec<u8>,
    pub server_cert_chain: Vec<Vec<u8>>,
    pub server_addr: String,
}

pub struct RDCleanPathError {
    pub error_code: i64,
    pub http_status_code: Option<i64>,
    pub wsa_last_error: Option<i64>,
    pub tls_alert_code: Option<i64>,
}

/// Parse an RDCleanPath Request PDU from raw DER bytes.
///
/// Layout (SEQUENCE):
///   [0] version  INTEGER   — must be 3390
///   [1] error    (skip)
///   [2] destination  UTF8String
///   [3] proxyAuth    UTF8String
///   [4] serverAuth   (skip)
///   [5] preconnectionBlob  UTF8String  (optional)
///   [6] x224ConnectionPdu  OCTET STRING
pub fn parse_request(data: &[u8]) -> Result<RDCleanPathRequest, String> {
    let mut outer = DerReader::new(data);
    let mut seq = outer.read_sequence()?;

    // [0] version
    let mut version_reader = seq
        .read_explicit(0)?
        .ok_or("RDCleanPath: missing [0] version")?;
    let version = version_reader.read_integer()?;
    if version != RDCLEANPATH_VERSION {
        return Err(format!(
            "RDCleanPath: unsupported version {version}, expected {RDCLEANPATH_VERSION}"
        ));
    }

    // [1] error — skip if present
    if let Some(mut _err_reader) = seq.read_explicit(1)? {
        // consume / ignore
    }

    // [2] destination
    let mut dest_reader = seq
        .read_explicit(2)?
        .ok_or("RDCleanPath: missing [2] destination")?;
    let destination = dest_reader.read_utf8_string()?;

    // [3] proxyAuth
    let mut auth_reader = seq
        .read_explicit(3)?
        .ok_or("RDCleanPath: missing [3] proxyAuth")?;
    let proxy_auth = auth_reader.read_utf8_string()?;

    // [4] serverAuth — skip if present
    if let Some(mut _sa_reader) = seq.read_explicit(4)? {
        // consume / ignore
    }

    // [5] preconnectionBlob (optional)
    let preconnection_blob = if let Some(mut pcb_reader) = seq.read_explicit(5)? {
        Some(pcb_reader.read_utf8_string()?)
    } else {
        None
    };

    // [6] x224ConnectionPdu
    let mut x224_reader = seq
        .read_explicit(6)?
        .ok_or("RDCleanPath: missing [6] x224ConnectionPdu")?;
    let x224_connection_pdu = x224_reader.read_octet_string()?;

    Ok(RDCleanPathRequest {
        version,
        destination,
        proxy_auth,
        preconnection_blob,
        x224_connection_pdu,
    })
}

/// Build an RDCleanPath Response PDU.
///
/// Layout (SEQUENCE):
///   [0] version  INTEGER
///   [6] x224ConnectionPdu  OCTET STRING
///   [7] serverCertChain  SEQUENCE OF OCTET STRING
///   [9] serverAddr  UTF8String
pub fn build_response(resp: &RDCleanPathResponse) -> Vec<u8> {
    let version_el = encode_explicit(0, &encode_integer(RDCLEANPATH_VERSION));

    let x224_el = encode_explicit(6, &encode_octet_string(&resp.x224_connection_pdu));

    // SEQUENCE OF OCTET STRING for cert chain
    let cert_elements: Vec<Vec<u8>> = resp
        .server_cert_chain
        .iter()
        .map(|c| encode_octet_string(c))
        .collect();
    let cert_seq = encode_sequence_from_vecs(&cert_elements);
    let cert_el = encode_explicit(7, &cert_seq);

    let addr_el = encode_explicit(9, &encode_utf8_string(&resp.server_addr));

    encode_sequence(&[&version_el, &x224_el, &cert_el, &addr_el])
}

/// Build an RDCleanPath Error PDU.
///
/// Layout (SEQUENCE):
///   [0] version  INTEGER
///   [1] error  SEQUENCE {
///     [0] errorCode  INTEGER
///     [1] httpStatusCode  INTEGER  (optional)
///     [2] wsaLastError  INTEGER  (optional)
///     [3] tlsAlertCode  INTEGER  (optional)
///   }
pub fn build_error(err: &RDCleanPathError) -> Vec<u8> {
    let version_el = encode_explicit(0, &encode_integer(RDCLEANPATH_VERSION));

    let mut error_fields = vec![encode_explicit(0, &encode_integer(err.error_code))];

    if let Some(http_status) = err.http_status_code {
        error_fields.push(encode_explicit(1, &encode_integer(http_status)));
    }
    if let Some(wsa_error) = err.wsa_last_error {
        error_fields.push(encode_explicit(2, &encode_integer(wsa_error)));
    }
    if let Some(tls_alert) = err.tls_alert_code {
        error_fields.push(encode_explicit(3, &encode_integer(tls_alert)));
    }

    let error_seq = encode_sequence_from_vecs(&error_fields);
    let error_el = encode_explicit(1, &error_seq);

    encode_sequence(&[&version_el, &error_el])
}
