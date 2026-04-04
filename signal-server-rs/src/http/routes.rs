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
