use axum::{extract::State, response::Json};
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

pub async fn gateways(State(state): State<AppState>) -> Json<Value> {
    let gateways: Vec<Value> = state.registry.get_all_gateways()
        .iter()
        .filter_map(|id| {
            state.registry.get_gateway(id).map(|gw| {
                json!({
                    "id": gw.id,
                    "displayName": gw.metadata.display_name,
                    "description": gw.metadata.description,
                    "backends": gw.metadata.backends,
                    "addresses": gw.addresses,
                    "clientCount": gw.paired_clients.len(),
                    "online": true,
                })
            })
        })
        .collect();
    Json(json!({ "gateways": gateways }))
}
