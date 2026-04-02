#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use std::sync::Arc;

mod auth;
mod config;
mod logstream;
mod proxy;
pub mod recording;
mod rdcleanpath;
mod setup;
mod stun;
mod tls;
mod tray;
pub mod vpn;
mod webrtc;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    // Init logging: stderr + broadcast to web UI
    // Default: INFO for our crate, WARN for dependencies
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;
        logstream::init();
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("punchd_bridge_rs=debug,warn")
        });
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(logstream::BroadcastLayer)
            .init();
    }

    // First-run setup: if no config, serve web UI
    setup::run_setup_if_needed().await;

    // Load config
    let config = config::load_config();
    let tc_config = config::load_tidecloak_config();
    // Auth
    let extra_issuers = config
        .auth_server_public_url
        .iter()
        .map(|s| s.clone())
        .chain(config.tc_internal_url.iter().map(|s| s.clone()))
        .collect::<Vec<_>>();
    let auth = Arc::new(auth::tidecloak::TidecloakAuth::new(
        &tc_config,
        &extra_issuers,
    ));

    // TLS
    let tls_cert = if config.https {
        Some(tls::generate_self_signed(&config.tls_hostname))
    } else {
        None
    };

    // HTTP Proxy
    let proxy_state = proxy::http_proxy::build_proxy_state(
        &config,
        &tc_config,
        auth.clone(),
        tls_cert.is_some(),
    );
    let (app, shared_state) = proxy::http_proxy::build_router(proxy_state.clone());

    // Bind HTTP(S) server
    let addr = format!("0.0.0.0:{}", config.listen_port);
    let scheme = if config.https { "https" } else { "http" };

    // Health + logs server on separate port (plain HTTP)
    let health_addr = format!("0.0.0.0:{}", config.health_port);
    let health_app = axum::Router::new()
        .route(
            "/health",
            axum::routing::get(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
        )
        .route("/logs", axum::routing::get(serve_logs_page))
        .route("/logs/stream", axum::routing::get(serve_logs_stream))
        .route("/logs/buffer", axum::routing::get(serve_logs_buffer));

    // VPN state — always enabled, auto-configures IP forwarding when a client connects
    let vpn_state = Arc::new(tokio::sync::Mutex::new(
        vpn::vpn_handler::VpnState::new("10.66.0.0/24", true),
    ));

    // STUN registration
    let local_addr = std::env::var("GATEWAY_ADDRESS").unwrap_or_else(|_| {
        hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    });
    let _stun_reg = stun::stun_client::register(stun::stun_client::StunRegistrationOptions {
        stun_server_url: config.stun_server_url.clone(),
        gateway_id: config.gateway_id.clone(),
        addresses: vec![format!("{}:{}", local_addr, config.listen_port)],
        listen_port: config.listen_port,
        ice_servers: config.ice_servers.clone(),
        turn_server: config.turn_server.clone(),
        turn_secret: Some(config.turn_secret.clone()),
        use_tls: config.https,
        api_secret: config.api_secret.clone(),
        metadata: {
            // Only advertise realm if this gateway hosts TideCloak locally.
            // If tc_internal_url points to a remote STUN relay, advertising the realm
            // causes the signal server to route /realms/ requests here, creating a loop.
            let hosts_tc_locally = match &config.tc_internal_url {
                None => true, // no override → using local auth-server-url
                Some(url) => {
                    let u = url.to_lowercase();
                    u.contains("localhost") || u.contains("127.0.0.1") || u.contains("[::1]")
                }
            };
            let mut meta = serde_json::json!({
                "displayName": config.display_name,
                "description": config.description,
                "backends": config.backends.iter().map(|b| {
                    let mut entry = serde_json::json!({
                        "name": b.name,
                        "protocol": b.protocol,
                    });
                    if b.auth == crate::config::BackendAuth::EdDSA {
                        entry["auth"] = serde_json::json!("eddsa");
                    }
                    entry
                }).collect::<Vec<_>>(),
            });
            if hosts_tc_locally {
                meta["realm"] = serde_json::json!(tc_config.realm);
            }
            meta
        },
        backends: config.backends.clone(),
        auth: Some(auth.clone()),
        vpn_state: Some(vpn_state.clone()),
    });

    // Watch config files for changes — hot-reload backends, auth, VPN settings
    {
        let shared = shared_state.clone();
        let use_tls = tls_cert.is_some();
        config::on_config_change(move || {
            tracing::info!("[Config] Hot-reloading config...");
            let new_config = config::load_config();
            let new_tc_config = config::load_tidecloak_config();
            let new_extra_issuers: Vec<String> = new_config.auth_server_public_url.iter()
                .chain(new_config.tc_internal_url.iter())
                .cloned().collect();
            let new_auth = Arc::new(auth::tidecloak::TidecloakAuth::new(&new_tc_config, &new_extra_issuers));

            proxy::http_proxy::reload_state(&shared, &new_config, &new_tc_config, new_auth, use_tls);
        });
    }
    config::watch_config_and_restart();

    // System tray icon
    let logs_url = format!("http://localhost:{}/logs", config.health_port);
    let gateway_url = format!("{scheme}://localhost:{}", config.listen_port);
    tray::spawn_tray(logs_url, gateway_url);

    // VPN toggle callback — enables/disables IP forwarding from the system tray
    tray::set_vpn_callback(|enabled| {
        if enabled {
            tracing::info!("[VPN] VPN enabled via system tray");
            vpn::vpn_handler::enable_forwarding();
        } else {
            tracing::info!("[VPN] VPN disabled via system tray");
            vpn::vpn_handler::disable_forwarding();
        }
    });

    // Startup banner
    tracing::info!("Punchd Gateway (local-facing)");
    tracing::info!(
        "Login: {scheme}://localhost:{}/login",
        config.listen_port
    );
    tracing::info!(
        "Proxy: {scheme}://localhost:{}",
        config.listen_port
    );
    tracing::info!(
        "Health: http://localhost:{}/health",
        config.health_port
    );
    for b in &config.backends {
        tracing::info!("Backend: {} -> {}", b.name, b.url);
    }
    tracing::info!("STUN Server: {}", config.stun_server_url);
    tracing::info!("Gateway ID: {}", config.gateway_id);

    // Start servers
    let _health_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&health_addr).await.unwrap();
        axum::serve(listener, health_app).await.unwrap();
    });

    if let Some(ref tls) = tls_cert {
        // HTTPS with rustls
        use tokio_rustls::TlsAcceptor;
        use rustls::ServerConfig as RustlsConfig;

        let certs = rustls_pemfile::certs(&mut tls.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut tls.key_pem.as_bytes())
            .unwrap()
            .unwrap();

        let rustls_config = RustlsConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let tls_acceptor = TlsAcceptor::from(Arc::new(rustls_config));

        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        tracing::info!("HTTPS listening on {addr}");

        // Accept TLS connections
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("Accept error: {}", e);
                    continue;
                }
            };
            let acceptor = tls_acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                if let Ok(tls_stream) = acceptor.accept(stream).await {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |req| {
                        let app = app.clone();
                        async move {
                            use tower::ServiceExt;
                            app.oneshot(req).await
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await;
                }
            });
        }
    } else {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        tracing::info!("HTTP listening on {addr}");
        axum::serve(listener, app).await.unwrap();
    }
}

// ── Logs handlers for the health server ─────────────────────────

use axum::response::{Html, Sse};
use axum::response::sse::Event;

async fn serve_logs_page() -> Html<&'static str> {
    Html(proxy::http_proxy::LOGS_HTML)
}

async fn serve_logs_stream() -> Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>> {
    use futures_util::StreamExt;
    use tokio_stream::wrappers::BroadcastStream;

    let rx = logstream::subscribe().expect("log stream not initialized");
    let stream = BroadcastStream::new(rx).filter_map(|result| async move {
        match result {
            Ok(line) => Some(Ok(Event::default().data(line))),
            Err(_) => None,
        }
    });
    Sse::new(stream)
}

async fn serve_logs_buffer() -> axum::Json<Vec<String>> {
    axum::Json(logstream::recent_lines())
}
