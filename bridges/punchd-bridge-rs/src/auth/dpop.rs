use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use sha2::{Digest, Sha256};

use super::tidecloak::{b64url_decode, b64url_encode};

static JTI_TTL_MS: u64 = 120_000;

pub struct DPoPVerifier {
    seen_jtis: DashMap<String, u64>,
}

impl DPoPVerifier {
    pub fn new() -> Self {
        Self {
            seen_jtis: DashMap::new(),
        }
    }

    fn check_and_store_jti(&self, jti: &str) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if self.seen_jtis.len() > 1000 {
            self.seen_jtis.retain(|_, exp| *exp > now_ms);
        }
        if self.seen_jtis.contains_key(jti) {
            return false;
        }
        self.seen_jtis.insert(jti.to_string(), now_ms + JTI_TTL_MS);
        true
    }

    pub fn verify_proof(
        &self,
        proof_jwt: &str,
        http_method: &str,
        http_url: &str,
        expected_jkt: Option<&str>,
    ) -> Result<(), String> {
        let parts: Vec<&str> = proof_jwt.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT structure".into());
        }

        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[0])?)
                .map_err(|e| format!("Header: {e}"))?;
        let payload: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[1])?)
                .map_err(|e| format!("Payload: {e}"))?;
        let sig = b64url_decode(parts[2])?;

        if header["typ"].as_str() != Some("dpop+jwt") {
            return Err("Invalid typ".into());
        }

        let alg = header["alg"].as_str().ok_or("Missing alg")?;
        if !["EdDSA", "ES256", "ES384", "ES512"].contains(&alg) {
            return Err(format!("Unsupported alg: {alg}"));
        }

        let jwk = header.get("jwk").ok_or("Missing jwk in header")?;

        // Verify signature
        let sign_input = format!("{}.{}", parts[0], parts[1]);
        let kty = jwk["kty"].as_str().ok_or("Missing kty")?;
        let valid = match (kty, alg) {
            ("OKP", "EdDSA") => {
                let x = jwk["x"].as_str().ok_or("Missing x")?;
                super::tidecloak::b64url_decode(x)
                    .and_then(|x_bytes| {
                        let pk = ring::signature::UnparsedPublicKey::new(
                            &ring::signature::ED25519,
                            &x_bytes,
                        );
                        Ok(pk.verify(sign_input.as_bytes(), &sig).is_ok())
                    })?
            }
            ("EC", alg) => {
                let x = jwk["x"].as_str().ok_or("Missing x")?;
                let y = jwk["y"].as_str().ok_or("Missing y")?;
                let alg_ring = match alg {
                    "ES256" => &ring::signature::ECDSA_P256_SHA256_FIXED,
                    "ES384" => &ring::signature::ECDSA_P384_SHA384_FIXED,
                    _ => return Err(format!("Unsupported EC alg: {alg}")),
                };
                let x_bytes = b64url_decode(x)?;
                let y_bytes = b64url_decode(y)?;
                let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                point.push(0x04);
                point.extend_from_slice(&x_bytes);
                point.extend_from_slice(&y_bytes);
                let pk = ring::signature::UnparsedPublicKey::new(alg_ring, &point);
                pk.verify(sign_input.as_bytes(), &sig).is_ok()
            }
            _ => return Err(format!("Unsupported DPoP key/alg: {kty}/{alg}")),
        };

        if !valid {
            return Err("Invalid signature".into());
        }

        // Check htm
        if payload["htm"].as_str() != Some(http_method) {
            return Err("htm mismatch".into());
        }

        // Check htu
        let expected_htu = http_url.split('?').next().unwrap_or(http_url);
        if payload["htu"].as_str() != Some(expected_htu) {
            return Err("htu mismatch".into());
        }

        // Check iat
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let iat = payload["iat"].as_u64().ok_or("Missing iat")?;
        if now.abs_diff(iat) > 120 {
            return Err("iat too far from current time".into());
        }

        // Check jti
        let jti = payload["jti"].as_str().ok_or("jti missing")?;
        if !self.check_and_store_jti(jti) {
            return Err("jti replayed".into());
        }

        // Check thumbprint
        if let Some(expected) = expected_jkt {
            let thumbprint = compute_jwk_thumbprint(jwk)?;
            if thumbprint != expected {
                return Err("JWK thumbprint does not match cnf.jkt".into());
            }
        }

        Ok(())
    }
}

pub fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
    let kty = jwk["kty"].as_str().ok_or("Missing kty")?;
    let canonical = match kty {
        "EC" => format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk["crv"].as_str().ok_or("Missing crv")?,
            kty,
            jwk["x"].as_str().ok_or("Missing x")?,
            jwk["y"].as_str().ok_or("Missing y")?,
        ),
        "OKP" => format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#,
            jwk["crv"].as_str().ok_or("Missing crv")?,
            kty,
            jwk["x"].as_str().ok_or("Missing x")?,
        ),
        "RSA" => format!(
            r#"{{"e":"{}","kty":"{}","n":"{}"}}"#,
            jwk["e"].as_str().ok_or("Missing e")?,
            kty,
            jwk["n"].as_str().ok_or("Missing n")?,
        ),
        other => return Err(format!("Unsupported key type: {other}")),
    };
    Ok(b64url_encode(&Sha256::digest(canonical.as_bytes())))
}

pub fn extract_cnf_jkt(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_bytes = b64url_decode(parts[1]).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload["cnf"]["jkt"].as_str().map(|s| s.to_string())
}
