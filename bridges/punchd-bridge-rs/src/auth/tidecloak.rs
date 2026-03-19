use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature;
use serde::Deserialize;

use crate::config::TidecloakConfig;

/// JWT payload fields we care about
#[derive(Deserialize, Clone, Debug)]
pub struct JwtPayload {
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub realm_access: Option<RealmAccess>,
    #[serde(default)]
    pub resource_access: Option<serde_json::Value>,
    #[serde(default)]
    pub cnf: Option<CnfClaim>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RealmAccess {
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct CnfClaim {
    #[serde(default)]
    pub jkt: Option<String>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| {
            let padded = match s.len() % 4 {
                2 => format!("{s}=="),
                3 => format!("{s}="),
                _ => s.to_string(),
            };
            base64::engine::general_purpose::URL_SAFE.decode(&padded)
        })
        .map_err(|e| format!("base64url decode: {e}"))
}

pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn verify_eddsa(sign_input: &[u8], sig: &[u8], x: &str) -> Result<bool, String> {
    let x_bytes = b64url_decode(x)?;
    let pk = signature::UnparsedPublicKey::new(&signature::ED25519, &x_bytes);
    Ok(pk.verify(sign_input, sig).is_ok())
}

fn verify_ec(sign_input: &[u8], sig: &[u8], alg: &str, x: &str, y: &str) -> Result<bool, String> {
    let alg_ring = match alg {
        "ES256" => &signature::ECDSA_P256_SHA256_FIXED,
        "ES384" => &signature::ECDSA_P384_SHA384_FIXED,
        _ => return Err(format!("Unsupported EC alg: {alg}")),
    };
    let x_bytes = b64url_decode(x)?;
    let y_bytes = b64url_decode(y)?;
    let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);
    let pk = signature::UnparsedPublicKey::new(alg_ring, &point);
    Ok(pk.verify(sign_input, sig).is_ok())
}

fn verify_jwt_sig(token: &str, config: &TidecloakConfig) -> Result<bool, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT structure".into());
    }

    let header_bytes = b64url_decode(parts[0])?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("Header parse: {e}"))?;

    let sign_input = format!("{}.{}", parts[0], parts[1]);
    let sig = b64url_decode(parts[2])?;

    let kid = header.kid.as_deref();
    let key = config
        .jwk
        .keys
        .iter()
        .find(|k| kid.is_none_or(|kid_val| k.kid == kid_val) && k.alg == header.alg)
        .or_else(|| config.jwk.keys.first())
        .ok_or("No matching key")?;

    match key.crv.as_str() {
        "Ed25519" => verify_eddsa(sign_input.as_bytes(), &sig, &key.x),
        "P-256" => verify_ec(
            sign_input.as_bytes(),
            &sig,
            "ES256",
            &key.x,
            key.y.as_deref().unwrap_or(""),
        ),
        "P-384" => verify_ec(
            sign_input.as_bytes(),
            &sig,
            "ES384",
            &key.x,
            key.y.as_deref().unwrap_or(""),
        ),
        _ => Err(format!("Unsupported curve: {}", key.crv)),
    }
}

pub fn parse_jwt_payload(token: &str) -> Result<JwtPayload, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT structure".into());
    }
    let payload_bytes = b64url_decode(parts[1])?;
    serde_json::from_slice(&payload_bytes).map_err(|e| format!("Payload parse: {e}"))
}

/// TideCloak auth verifier
#[derive(Clone)]
pub struct TidecloakAuth {
    config: Arc<TidecloakConfig>,
    valid_issuers: Vec<String>,
}

impl TidecloakAuth {
    pub fn new(config: &TidecloakConfig, extra_issuers: &[String]) -> Self {
        let base_url = config.auth_server_url.trim_end_matches('/');
        let primary_issuer = format!("{base_url}/realms/{}", config.realm);

        let mut valid_issuers = vec![primary_issuer];
        for base in extra_issuers {
            let url = base.trim_end_matches('/');
            valid_issuers.push(format!("{url}/realms/{}", config.realm));
        }

        tracing::info!("TideCloak JWKS loaded successfully");
        tracing::info!("Valid issuers: {}", valid_issuers.join(", "));

        Self {
            config: Arc::new(config.clone()),
            valid_issuers,
        }
    }

    pub async fn verify_token(&self, token: &str) -> Option<JwtPayload> {
        let payload = parse_jwt_payload(token).ok()?;

        // Check issuer
        let iss = payload.iss.as_deref()?;
        if !self.valid_issuers.iter().any(|i| i == iss) {
            tracing::error!("Issuer mismatch: got {iss}");
            return None;
        }

        // Check azp
        if payload.azp.as_deref() != Some(&self.config.resource) {
            tracing::error!(
                "AZP mismatch: expected {}, got {:?}",
                self.config.resource, payload.azp
            );
            return None;
        }

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(exp) = payload.exp {
            if now > exp {
                tracing::error!("Token expired");
                return None;
            }
        }

        // Verify signature
        match verify_jwt_sig(token, &self.config) {
            Ok(true) => Some(payload),
            Ok(false) => {
                tracing::error!("JWT signature verification failed");
                None
            }
            Err(e) => {
                tracing::error!("JWT verification error: {e}");
                None
            }
        }
    }
}
