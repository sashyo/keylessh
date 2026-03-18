use std::sync::Arc;

mod auth;
mod config;
mod logstream;
mod proxy;
mod rdcleanpath;
mod setup;
mod stun;
mod tls;
mod tray;
mod webrtc;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    // Init logging: stderr + broadcast to web UI
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        logstream::init();
        tracing_subscriber::registry()
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
    let app = proxy::http_proxy::build_router(proxy_state.clone());

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
        .route("/logs/stream", axum::routing::get(serve_logs_stream));

    // STUN registration
    let local_addr = std::env::var("GATEWAY_ADDRESS").unwrap_or_else(|_| {
        hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    });
    let stun_reg = stun::stun_client::register(stun::stun_client::StunRegistrationOptions {
        stun_server_url: config.stun_server_url.clone(),
        gateway_id: config.gateway_id.clone(),
        addresses: vec![format!("{}:{}", local_addr, config.listen_port)],
        listen_port: config.listen_port,
        ice_servers: config.ice_servers.clone(),
        turn_server: config.turn_server.clone(),
        turn_secret: Some(config.turn_secret.clone()),
        use_tls: config.https,
        api_secret: config.api_secret.clone(),
        metadata: serde_json::json!({
            "displayName": config.display_name,
            "description": config.description,
            "backends": config.backends.iter().map(|b| serde_json::json!({
                "name": b.name,
                "protocol": b.protocol,
            })).collect::<Vec<_>>(),
            "realm": tc_config.realm,
        }),
        backends: config.backends.clone(),
        auth: Some(auth.clone()),
        tc_client_id: Some(tc_config.resource.clone()),
    });

    // System tray icon
    let logs_url = format!("http://localhost:{}/logs", config.health_port);
    let gateway_url = format!("{scheme}://localhost:{}", config.listen_port);
    tray::spawn_tray(logs_url, gateway_url);

    // Startup banner
    eprintln!("[Gateway] KeyleSSH Gateway (local-facing)");
    eprintln!(
        "[Gateway] Login: {scheme}://localhost:{}/login",
        config.listen_port
    );
    eprintln!(
        "[Gateway] Proxy: {scheme}://localhost:{}",
        config.listen_port
    );
    eprintln!(
        "[Gateway] Health: http://localhost:{}/health",
        config.health_port
    );
    for b in &config.backends {
        eprintln!("[Gateway] Backend: {} -> {}", b.name, b.url);
    }
    eprintln!("[Gateway] STUN Server: {}", config.stun_server_url);
    eprintln!("[Gateway] Gateway ID: {}", config.gateway_id);

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
        eprintln!("[Gateway] HTTPS listening on {addr}");

        // Accept TLS connections
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("[Gateway] Accept error: {}", e);
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
                        .await;
                }
            });
        }
    } else {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        eprintln!("[Gateway] HTTP listening on {addr}");
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
