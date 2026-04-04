mod config;
mod state;
mod registry;
mod signaling;
mod relay;
mod proxy;
mod quic;
mod http;

use axum::{routing::get, Router};
use std::net::SocketAddr;
use tower_http::cors::{CorsLayer, Any};

use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Config::from_env();
    let use_tls = config.use_tls();
    let port = config.port;
    let state = AppState::new(config);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(http::routes::health))
        .route("/webrtc-config", get(http::routes::webrtc_config))
        .route("/api/gateways", get(http::routes::gateways))
        .route("/ws/ssh", get(proxy::ssh::ssh_ws_handler))
        // WebSocket signaling on root path
        .route("/", get(signaling::handler::ws_handler))
        // Everything else: HTTP relay to gateway
        .fallback(relay::http_relay::relay_handler)
        .layer(cors)
        .with_state(state.clone());

    let scheme = if use_tls { "https" } else { "http" };
    let ws_scheme = if use_tls { "wss" } else { "ws" };

    tracing::info!("[Signal] Signal Server listening on {scheme}://localhost:{port}");
    tracing::info!("[Signal] Signaling: {ws_scheme}://localhost:{port}");
    tracing::info!("[Signal] Health: {scheme}://localhost:{port}/health");

    if !state.config.api_secret.is_empty() {
        tracing::info!("[Signal] API Secret: set");
    }

    // Start QUIC relay endpoint (WebTransport on UDP)
    if let (Some(ref cert), Some(ref key)) = (&state.config.tls_cert_path, &state.config.tls_key_path) {
        let relay_state = state.clone();
        let cert = cert.clone();
        let key = key.clone();
        let relay_port = state.config.relay_port;
        tokio::spawn(async move {
            quic::endpoint::start_relay_endpoint(relay_state, &cert, &key, relay_port).await;
        });
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    if use_tls {
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            state.config.tls_cert_path.as_ref().unwrap(),
            state.config.tls_key_path.as_ref().unwrap(),
        )
        .await
        .expect("Failed to load TLS certs");

        tracing::info!("[Signal] TLS: {}", state.config.tls_cert_path.as_ref().unwrap());

        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("Server failed");
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await.expect("Bind failed");
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("Server failed");
    }
}
