use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::config::TidecloakConfig;

#[derive(Clone, Debug)]
pub struct OidcEndpoints {
    pub authorization: String,
    pub token: String,
    pub logout: String,
}

#[derive(Deserialize, Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub refresh_expires_in: Option<u64>,
    pub token_type: String,
}

pub fn get_oidc_endpoints(config: &TidecloakConfig, base_url_override: Option<&str>) -> OidcEndpoints {
    let base = base_url_override
        .unwrap_or(&config.auth_server_url)
        .trim_end_matches('/');
    let realm_path = format!("{base}/realms/{}/protocol/openid-connect", config.realm);

    OidcEndpoints {
        authorization: format!("{realm_path}/auth"),
        token: format!("{realm_path}/token"),
        logout: format!("{realm_path}/logout"),
    }
}

pub fn build_auth_url(
    endpoints: &OidcEndpoints,
    client_id: &str,
    redirect_uri: &str,
    original_url: &str,
) -> (String, String) {
    let nonce = hex::encode(&random_bytes());
    let state_json = serde_json::json!({
        "nonce": nonce,
        "redirect": if original_url.is_empty() { "/" } else { original_url },
    });
    let state = URL_SAFE_NO_PAD.encode(state_json.to_string().as_bytes());

    let params = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .finish();

    (format!("{}?{params}", endpoints.authorization), state)
}

pub async fn exchange_code(
    endpoints: &OidcEndpoints,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<TokenResponse, String> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client_id)
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .finish();

    post_token_request(&endpoints.token, &body, "Token exchange").await
}

pub async fn refresh_access_token(
    endpoints: &OidcEndpoints,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse, String> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", client_id)
        .append_pair("refresh_token", refresh_token)
        .finish();

    post_token_request(&endpoints.token, &body, "Token refresh").await
}

async fn post_token_request(
    token_url: &str,
    body: &str,
    label: &str,
) -> Result<TokenResponse, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("{label} client error: {e}"))?;

    let resp = client
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("{label} network error: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("{label} read error: {e}"))?;

    if !status.is_success() {
        tracing::error!("{label} failed ({status}): {text}");
        return Err(format!("{label} failed ({status}): {text}"));
    }

    serde_json::from_str(&text).map_err(|e| {
        tracing::error!("{label} response not JSON: {}", &text[..200.min(text.len())]);
        format!("{label} response not JSON: {e}")
    })
}

pub fn build_logout_url(
    endpoints: &OidcEndpoints,
    client_id: &str,
    post_logout_redirect_uri: &str,
) -> String {
    let params = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("post_logout_redirect_uri", post_logout_redirect_uri)
        .finish();
    format!("{}?{params}", endpoints.logout)
}

pub fn parse_state(state: &str) -> (String, String) {
    let bytes = URL_SAFE_NO_PAD.decode(state).unwrap_or_default();
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        let nonce = val["nonce"].as_str().unwrap_or("").to_string();
        let redirect = val["redirect"].as_str().unwrap_or("/").to_string();
        (nonce, redirect)
    } else {
        (String::new(), "/".to_string())
    }
}

// hex helper
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

use rand::Rng;

fn random_bytes() -> [u8; 16] {
    rand::rng().random::<[u8; 16]>()
}
