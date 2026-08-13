use axum::{
    extract::{Query, State},
    response::Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::http::turn::generate_turn_credentials;
use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "gateways": state.registry.gateway_count(),
        "clients": state.registry.client_count(),
    }))
}

pub async fn webrtc_config(State(state): State<AppState>) -> Json<Value> {
    let config = &state.config;

    let mut result = json!({});

    if !config.ice_servers.is_empty() {
        result["stunServer"] = json!(config.ice_servers[0]);
    }

    if let Some(ref turn_server) = config.turn_server {
        if !config.turn_secret.is_empty() {
            let (username, password) = generate_turn_credentials(&config.turn_secret, 86400);
            result["turnServer"] = json!(turn_server);
            result["turnUsername"] = json!(username);
            result["turnPassword"] = json!(password);
        }
    }

    // Include backend auth info per gateway so clients can detect EdDSA backends
    // without a separate fetch (avoids Private Network Access prompt)
    let mut gw_backends: serde_json::Map<String, Value> = serde_json::Map::new();
    for gw_id in state.registry.get_all_gateways() {
        if let Some(gw) = state.registry.get_gateway(&gw_id) {
            if let Some(ref backends) = gw.metadata.backends {
                let mut auth_map: serde_json::Map<String, Value> = serde_json::Map::new();
                for b in backends {
                    if let Some(ref auth) = b.auth {
                        auth_map.insert(b.name.clone(), json!(auth));
                    }
                }
                if !auth_map.is_empty() {
                    gw_backends.insert(gw.id.clone(), Value::Object(auth_map));
                }
            }
        }
    }
    if !gw_backends.is_empty() {
        result["gatewayBackendAuth"] = Value::Object(gw_backends);
    }

    Json(result)
}

#[derive(Debug, Default, Deserialize)]
pub struct GatewaysQuery {
    /// Only return gateways trusting this TideCloak issuer. Gateways that do not
    /// advertise an issuer (older builds) are always returned, so an in-progress
    /// rollout never blanks a tenant's list.
    pub issuer: Option<String>,
}

pub async fn gateways(
    State(state): State<AppState>,
    Query(query): Query<GatewaysQuery>,
) -> Json<Value> {
    let want_issuer = query.issuer.as_deref().map(|s| s.trim_end_matches('/'));
    let gateways: Vec<Value> = state.registry.get_all_gateways()
        .iter()
        .filter_map(|id| {
            state.registry.get_gateway(id).and_then(|gw| {
                if let (Some(want), Some(have)) = (want_issuer, gw.metadata.issuer.as_deref()) {
                    if !want.eq_ignore_ascii_case(have.trim_end_matches('/')) {
                        return None;
                    }
                }
                Some(json!({
                    "id": gw.id,
                    "displayName": gw.metadata.display_name,
                    "description": gw.metadata.description,
                    "backends": gw.metadata.backends,
                    "addresses": gw.addresses,
                    "clientCount": gw.paired_clients.len(),
                    "online": true,
                    "issuer": gw.metadata.issuer,
                    "clientId": gw.metadata.client_id,
                    "config": gw.metadata.config,
                }))
            })
        })
        .collect();
    Json(json!({ "gateways": gateways }))
}

/// How long to wait for a gateway to confirm it applied a pushed config.
const CONFIG_PUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Build the `config_update` frame sent down a gateway's WebSocket.
pub fn config_update_message(request_id: &str, config: &Value) -> String {
    json!({
        "type": "config_update",
        "requestId": request_id,
        "config": config,
    })
    .to_string()
}

/// POST /api/gateways/{id}/config — push config to a gateway.
///
/// Authenticated with the same shared API secret gateways use to register, so
/// no new credential is introduced. The gateway itself refuses any field that
/// would change which TideCloak it trusts, which is what keeps this secret from
/// being an authentication bypass.
pub async fn push_gateway_config(
    State(state): State<AppState>,
    axum::extract::Path(gateway_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    Json(config): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;

    if !state.config.api_secret.is_empty() {
        let presented = headers
            .get("x-api-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if presented != state.config.api_secret {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid API secret" })),
            );
        }
    }

    if !config.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Config must be a JSON object" })),
        );
    }

    let request_id = uuid::Uuid::new_v4().to_string();

    // Offline gateway: hold the config and hand it over when it next registers.
    if state.registry.get_gateway(&gateway_id).is_none() {
        state.pending_configs.insert(gateway_id.clone(), config);
        tracing::info!("[Signal] Gateway {gateway_id} offline — config queued for next registration");
        return (
            StatusCode::ACCEPTED,
            Json(json!({
                "delivered": false,
                "pending": true,
                "message": "Gateway offline — config queued for its next registration",
            })),
        );
    }

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    state.pending_config_acks.insert(request_id.clone(), ack_tx);

    let sent = state.registry.send_to_gateway(
        &gateway_id,
        axum::extract::ws::Message::Text(config_update_message(&request_id, &config).into()),
    );

    if !sent {
        state.pending_config_acks.remove(&request_id);
        state.pending_configs.insert(gateway_id.clone(), config);
        return (
            StatusCode::ACCEPTED,
            Json(json!({
                "delivered": false,
                "pending": true,
                "message": "Gateway connection closed — config queued for its next registration",
            })),
        );
    }

    match tokio::time::timeout(CONFIG_PUSH_TIMEOUT, ack_rx).await {
        Ok(Ok(ack)) => (
            StatusCode::OK,
            Json(json!({
                "delivered": true,
                "pending": false,
                "applied": ack.get("applied").cloned().unwrap_or(json!([])),
                "rejected": ack.get("rejected").cloned().unwrap_or(json!([])),
                "changed": ack.get("changed").cloned().unwrap_or(json!(false)),
                "error": ack.get("error").cloned().unwrap_or(Value::Null),
            })),
        ),
        // Gateway dropped before acking.
        Ok(Err(_)) => {
            state.pending_config_acks.remove(&request_id);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "delivered": false, "error": "Gateway disconnected before confirming" })),
            )
        }
        Err(_) => {
            state.pending_config_acks.remove(&request_id);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({ "delivered": false, "error": "Gateway did not confirm within 15s" })),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::registry::GatewayMetadata;
    use tokio::sync::mpsc;

    fn state() -> AppState {
        AppState::new(Config::from_env())
    }

    fn register(st: &AppState, id: &str, issuer: Option<&str>) {
        let (tx, _rx) = mpsc::unbounded_channel();
        let meta = GatewayMetadata {
            display_name: None,
            description: None,
            backends: None,
            realm: None,
            issuer: issuer.map(|s| s.to_string()),
            client_id: None,
            config: None,
            public_url: None,
        };
        st.registry.register_gateway(id.into(), vec![], tx, meta, None);
    }

    fn ids(res: &Json<Value>) -> Vec<String> {
        let mut v: Vec<String> = res["gateways"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["id"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    }

    /// Register a gateway and keep its channel open so pushes can reach it.
    fn register_live(st: &AppState, id: &str) -> mpsc::UnboundedReceiver<axum::extract::ws::Message> {
        let (tx, rx) = mpsc::unbounded_channel();
        let meta = GatewayMetadata {
            display_name: None,
            description: None,
            backends: None,
            realm: None,
            issuer: None,
            client_id: None,
            config: None,
            public_url: None,
        };
        st.registry.register_gateway(id.into(), vec![], tx, meta, None);
        rx
    }

    fn secured_state(secret: &str) -> AppState {
        let mut config = Config::from_env();
        config.api_secret = secret.to_string();
        AppState::new(config)
    }

    fn secret_header(secret: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-api-secret", secret.parse().unwrap());
        h
    }

    const DEMO: &str = "https://tc.example.com/realms/demo";
    const DEVOPS: &str = "https://tc.example.com/realms/devops";

    #[tokio::test]
    async fn no_issuer_query_returns_every_gateway() {
        let st = state();
        register(&st, "demo-gw", Some(DEMO));
        register(&st, "devops-gw", Some(DEVOPS));

        let res = gateways(State(st), Query(GatewaysQuery::default())).await;
        assert_eq!(ids(&res), vec!["demo-gw", "devops-gw"]);
    }

    #[tokio::test]
    async fn issuer_query_excludes_other_tenants() {
        let st = state();
        register(&st, "demo-gw", Some(DEMO));
        register(&st, "devops-gw", Some(DEVOPS));

        let q = GatewaysQuery { issuer: Some(DEMO.into()) };
        let res = gateways(State(st), Query(q)).await;
        assert_eq!(ids(&res), vec!["demo-gw"]);
    }

    #[tokio::test]
    async fn trailing_slash_and_case_do_not_split_a_tenant() {
        let st = state();
        register(&st, "demo-gw", Some("https://TC.example.com/realms/demo/"));

        let q = GatewaysQuery { issuer: Some(DEMO.into()) };
        let res = gateways(State(st), Query(q)).await;
        assert_eq!(ids(&res), vec!["demo-gw"]);
    }

    #[tokio::test]
    async fn gateways_without_an_issuer_stay_visible() {
        let st = state();
        register(&st, "legacy-gw", None);
        register(&st, "devops-gw", Some(DEVOPS));

        let q = GatewaysQuery { issuer: Some(DEMO.into()) };
        let res = gateways(State(st), Query(q)).await;
        assert_eq!(ids(&res), vec!["legacy-gw"]);
    }

    #[tokio::test]
    async fn issuer_is_exposed_to_consoles() {
        let st = state();
        register(&st, "demo-gw", Some(DEMO));

        let res = gateways(State(st), Query(GatewaysQuery::default())).await;
        assert_eq!(res["gateways"][0]["issuer"].as_str(), Some(DEMO));
    }

    // ── Config push ──────────────────────────────────────────────

    use axum::extract::Path;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn push_requires_the_api_secret() {
        let st = secured_state("correct-secret");
        register_live(&st, "gw-1");

        let (status, body) = push_gateway_config(
            State(st.clone()),
            Path("gw-1".into()),
            secret_header("wrong-secret"),
            Json(json!({ "backends": "App=http://10.0.0.5:8080" })),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"].as_str(), Some("Invalid API secret"));
        assert!(st.pending_configs.is_empty(), "a rejected push must not be queued");
    }

    #[tokio::test]
    async fn push_rejects_a_non_object_body() {
        let st = state();
        register_live(&st, "gw-1");

        let (status, _) = push_gateway_config(
            State(st),
            Path("gw-1".into()),
            axum::http::HeaderMap::new(),
            Json(json!("not-an-object")),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn push_to_an_offline_gateway_is_queued() {
        let st = state();

        let (status, body) = push_gateway_config(
            State(st.clone()),
            Path("never-connected".into()),
            axum::http::HeaderMap::new(),
            Json(json!({ "backends": "App=http://10.0.0.5:8080" })),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["pending"].as_bool(), Some(true));
        assert_eq!(body["delivered"].as_bool(), Some(false));
        let queued = st.pending_configs.get("never-connected").expect("config queued");
        assert_eq!(queued["backends"].as_str(), Some("App=http://10.0.0.5:8080"));
    }

    #[tokio::test]
    async fn a_newer_queued_push_supersedes_the_older_one() {
        let st = state();
        for backends in ["App=http://old:8080", "App=http://new:8080"] {
            push_gateway_config(
                State(st.clone()),
                Path("offline-gw".into()),
                axum::http::HeaderMap::new(),
                Json(json!({ "backends": backends })),
            )
            .await;
        }

        assert_eq!(st.pending_configs.len(), 1);
        let queued = st.pending_configs.get("offline-gw").unwrap();
        assert_eq!(queued["backends"].as_str(), Some("App=http://new:8080"));
    }

    #[tokio::test]
    async fn push_delivers_to_an_online_gateway_and_returns_its_ack() {
        let st = secured_state("s3cret");
        let mut rx = register_live(&st, "gw-1");

        // Stand in for the gateway: read the frame, ack what it applied.
        let acking = tokio::spawn({
            let st = st.clone();
            async move {
                let msg = rx.recv().await.expect("gateway receives the push");
                let text = match msg {
                    axum::extract::ws::Message::Text(t) => t.to_string(),
                    other => panic!("expected a text frame, got {other:?}"),
                };
                let frame: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(frame["type"].as_str(), Some("config_update"));
                assert_eq!(frame["config"]["backends"].as_str(), Some("App=http://10.0.0.5:8080"));

                let request_id = frame["requestId"].as_str().unwrap().to_string();
                let (_, ack_tx) = st.pending_config_acks.remove(&request_id).expect("ack registered");
                ack_tx
                    .send(json!({
                        "applied": ["backends"],
                        "rejected": [{ "field": "api_secret", "reason": "set locally on the gateway only" }],
                        "changed": true,
                    }))
                    .unwrap();
            }
        });

        let (status, body) = push_gateway_config(
            State(st.clone()),
            Path("gw-1".into()),
            secret_header("s3cret"),
            Json(json!({ "backends": "App=http://10.0.0.5:8080", "api_secret": "nope" })),
        )
        .await;

        acking.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["delivered"].as_bool(), Some(true));
        assert_eq!(body["changed"].as_bool(), Some(true));
        assert_eq!(body["applied"][0].as_str(), Some("backends"));
        assert_eq!(body["rejected"][0]["field"].as_str(), Some("api_secret"));
        assert!(st.pending_config_acks.is_empty(), "the ack slot must be cleaned up");
        assert!(st.pending_configs.is_empty(), "a delivered push must not also queue");
    }

    #[tokio::test]
    async fn push_to_a_closed_connection_falls_back_to_queueing() {
        let st = state();
        // Registered, but the receiving end is gone — a gateway that dropped
        // without the registry noticing yet.
        let rx = register_live(&st, "gw-1");
        drop(rx);

        let (status, body) = push_gateway_config(
            State(st.clone()),
            Path("gw-1".into()),
            axum::http::HeaderMap::new(),
            Json(json!({ "backends": "App=http://10.0.0.5:8080" })),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["pending"].as_bool(), Some(true));
        assert!(st.pending_configs.contains_key("gw-1"));
        assert!(st.pending_config_acks.is_empty(), "the ack slot must be cleaned up");
    }
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use crate::config::Config;
    use axum::routing::{get, post};
    use axum::Router;

    /// Router construction panics on a malformed path (axum 0.8 requires `{id}`,
    /// not the old `:id`). The handler tests call functions directly and would
    /// not catch that, so build the real routes here — a panic means the binary
    /// dies at startup and never binds its port.
    #[test]
    fn routes_build_without_panicking() {
        let state = AppState::new(Config::from_env());
        let _app: Router = Router::new()
            .route("/health", get(health))
            .route("/webrtc-config", get(webrtc_config))
            .route("/api/gateways", get(gateways))
            .route("/api/gateways/{id}/config", post(push_gateway_config))
            .with_state(state);
    }
}
