///! WebView-based OIDC authentication for the VPN client.
///!
///! Opens an embedded browser window (WebView2 on Windows, webkit2gtk on Linux,
///! WKWebView on macOS) that loads the KeyleSSH web app. The full TideCloak
///! OIDC + Heimdall DPoP flow runs inside the webview — no external browser needed.
///!
///! After login, the token is extracted via JavaScript bridge and returned.
///! The webview stays alive (hidden) to refresh tokens and generate DPoP proofs
///! on demand.
///!
///! Build with `--features webview` to enable.

use std::sync::{Mutex, OnceLock};

/// Global store for the latest token from the WebView.
static LATEST_TOKEN: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn token_store() -> &'static Mutex<Option<String>> {
    LATEST_TOKEN.get_or_init(|| Mutex::new(None))
}

/// Get the latest token from the WebView (if one has been received).
pub fn get_latest_token() -> Option<String> {
    token_store().lock().ok()?.clone()
}

fn set_latest_token(token: &str) {
    if let Ok(mut store) = token_store().lock() {
        *store = Some(token.to_string());
    }
}

/// Global channel for DPoP proof responses (WebView JS → Rust).
static DPOP_RESPONSE_TX: OnceLock<Mutex<Option<std::sync::mpsc::SyncSender<String>>>> = OnceLock::new();

fn set_dpop_response(proof: &str) {
    if let Ok(guard) = DPOP_RESPONSE_TX.get_or_init(|| Mutex::new(None)).lock() {
        if let Some(ref tx) = *guard {
            let _ = tx.try_send(proof.to_string());
        }
    }
}

/// Global event loop proxy for sending messages to the WebView thread.
#[cfg(feature = "webview")]
static EVENT_PROXY: OnceLock<Mutex<Option<tao::event_loop::EventLoopProxy<String>>>> = OnceLock::new();

#[cfg(feature = "webview")]
fn send_to_webview(msg: &str) {
    if let Ok(guard) = EVENT_PROXY.get_or_init(|| Mutex::new(None)).lock() {
        if let Some(ref proxy) = *guard {
            let _ = proxy.send_event(msg.to_string());
        }
    }
}

/// Request a DPoP proof from the WebView.
/// The WebView JS signs a DPoP JWT using the Heimdall key in IndexedDB.
/// Returns the DPoP proof JWT string.
#[cfg(feature = "webview")]
pub async fn request_dpop_proof(method: &str, url: &str) -> Result<String, String> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1);

    // Register the response channel
    {
        let mut guard = DPOP_RESPONSE_TX.get_or_init(|| Mutex::new(None)).lock()
            .map_err(|_| "Lock error")?;
        *guard = Some(tx);
    }

    // Ask WebView to generate proof
    let request = serde_json::json!({
        "type": "dpop_request",
        "method": method,
        "url": url,
    });
    send_to_webview(&format!("dpop:{}", request));

    // Wait for response (5s timeout)
    let proof = tokio::task::spawn_blocking(move || {
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| format!("DPoP proof timeout: {e}"))
    })
    .await
    .map_err(|e| format!("DPoP task error: {e}"))??;

    // Clear the response channel
    {
        if let Ok(mut guard) = DPOP_RESPONSE_TX.get_or_init(|| Mutex::new(None)).lock() {
            *guard = None;
        }
    }

    Ok(proof)
}

#[cfg(not(feature = "webview"))]
pub async fn request_dpop_proof(_method: &str, _url: &str) -> Result<String, String> {
    Err("DPoP not available without webview feature".into())
}

// ── WebView implementation (feature-gated) ─────────────────────────

#[cfg(feature = "webview")]
mod imp {
    use super::{set_latest_token, set_dpop_response, EVENT_PROXY};

    /// Embedded WebView2Loader.dll — extracted next to the exe at runtime.
    #[cfg(target_os = "windows")]
    static WEBVIEW2_LOADER_DLL: &[u8] = include_bytes!("../../webview2/WebView2Loader_amd64.dll");

    #[cfg(target_os = "windows")]
    fn ensure_webview2_loader() {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_default();
        let dll_path = exe_dir.join("WebView2Loader.dll");
        if !dll_path.exists() {
            let _ = std::fs::write(&dll_path, WEBVIEW2_LOADER_DLL);
        }
    }

    pub struct WebViewAuthConfig {
        pub app_url: String,
        pub title: String,
        pub width: u32,
        pub height: u32,
    }

    impl Default for WebViewAuthConfig {
        fn default() -> Self {
            Self {
                app_url: std::env::var("SERVER_URL")
                    .unwrap_or_else(|_| "https://demo.keylessh.com".to_string()),
                title: "Punchd VPN - Login".to_string(),
                width: 500,
                height: 700,
            }
        }
    }

    pub fn open_auth_webview(
        config: WebViewAuthConfig,
        initial_token_tx: std::sync::mpsc::SyncSender<String>,
    ) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        ensure_webview2_loader();

        use tao::event::{Event, WindowEvent};
        use tao::event_loop::{ControlFlow, EventLoopBuilder};
        use tao::window::WindowBuilder;
        use wry::WebViewBuilder;

        let mut builder = EventLoopBuilder::<String>::with_user_event();
        #[cfg(target_os = "windows")]
        {
            use tao::platform::windows::EventLoopBuilderExtWindows;
            builder.with_any_thread(true);
        }
        let event_loop = builder.build();
        let proxy = event_loop.create_proxy();

        // Store proxy globally so other threads can request DPoP proofs
        {
            let mut guard = EVENT_PROXY.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap();
            *guard = Some(proxy.clone());
        }

        let window = WindowBuilder::new()
            .with_title(&config.title)
            .with_inner_size(tao::dpi::LogicalSize::new(config.width, config.height))
            .with_resizable(true)
            .build(&event_loop)
            .map_err(|e| format!("Failed to create window: {e}"))?;

        // JavaScript: polls for token + handles DPoP proof requests
        let init_script = r#"
            (function() {
                let lastToken = null;
                let sentInitialToken = false;

                // ── Token polling ──
                function checkToken() {
                    const token = localStorage.getItem("access_token");
                    if (token && token !== lastToken) {
                        lastToken = token;
                        window.ipc.postMessage(JSON.stringify({
                            type: "token",
                            token: token,
                            initial: !sentInitialToken,
                        }));
                        sentInitialToken = true;
                    }
                }
                setInterval(checkToken, 1000);
                window.addEventListener("storage", function(e) {
                    if (e.key === "access_token" && e.newValue) checkToken();
                });
                checkToken();

                // ── DPoP proof generation ──
                // Stores the DPoP key pair after first retrieval
                let dpopKeyCache = null;

                async function getDPoPKey() {
                    if (dpopKeyCache) return dpopKeyCache;

                    // Find the DPoP IndexedDB database
                    const dbs = await indexedDB.databases();
                    const dpopDb = dbs.find(d => d.name && d.name.startsWith("dpop:"));
                    if (!dpopDb) throw new Error("No DPoP database found");

                    const db = await new Promise((resolve, reject) => {
                        const req = indexedDB.open(dpopDb.name);
                        req.onsuccess = () => resolve(req.result);
                        req.onerror = () => reject(req.error);
                    });

                    const dpopState = await new Promise((resolve, reject) => {
                        const tx = db.transaction("main", "readonly");
                        const store = tx.objectStore("main");
                        const req = store.get("dpopState");
                        req.onsuccess = () => resolve(req.result);
                        req.onerror = () => reject(req.error);
                    });
                    db.close();

                    if (!dpopState || !dpopState.keys) throw new Error("No DPoP keys in IndexedDB");
                    dpopKeyCache = dpopState.keys;
                    return dpopKeyCache;
                }

                // Base64url encode
                function b64url(buf) {
                    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
                    return btoa(String.fromCharCode(...bytes))
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                }

                async function generateDPoPProof(method, url) {
                    const keys = await getDPoPKey();
                    const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);

                    // Determine algorithm
                    const algName = keys.privateKey.algorithm.name;
                    let alg, signParams;
                    if (algName === "Ed25519" || (algName === "ECDSA" && keys.privateKey.algorithm.namedCurve === undefined)) {
                        alg = "EdDSA";
                        signParams = { name: algName };
                    } else if (algName === "ECDSA") {
                        const curve = keys.privateKey.algorithm.namedCurve;
                        const hashMap = { "P-256": "SHA-256", "P-384": "SHA-384", "P-521": "SHA-512" };
                        alg = { "P-256": "ES256", "P-384": "ES384", "P-521": "ES512" }[curve] || "ES256";
                        signParams = { name: "ECDSA", hash: hashMap[curve] || "SHA-256" };
                    } else {
                        throw new Error("Unsupported key algorithm: " + algName);
                    }

                    // Build the DPoP JWT
                    const jwkForHeader = {};
                    if (publicJwk.kty) jwkForHeader.kty = publicJwk.kty;
                    if (publicJwk.crv) jwkForHeader.crv = publicJwk.crv;
                    if (publicJwk.x) jwkForHeader.x = publicJwk.x;
                    if (publicJwk.y) jwkForHeader.y = publicJwk.y;

                    const header = { typ: "dpop+jwt", alg: alg, jwk: jwkForHeader };
                    const payload = {
                        jti: crypto.randomUUID(),
                        htm: method,
                        htu: url,
                        iat: Math.floor(Date.now() / 1000),
                    };

                    const enc = new TextEncoder();
                    const headerB64 = b64url(enc.encode(JSON.stringify(header)));
                    const payloadB64 = b64url(enc.encode(JSON.stringify(payload)));
                    const sigInput = enc.encode(headerB64 + "." + payloadB64);

                    const sig = await crypto.subtle.sign(signParams, keys.privateKey, sigInput);
                    const sigB64 = b64url(sig);

                    return headerB64 + "." + payloadB64 + "." + sigB64;
                }

                // Listen for DPoP proof requests from Rust (via evaluate_script)
                window.__generateDPoPProof = async function(method, url) {
                    try {
                        const proof = await generateDPoPProof(method, url);
                        window.ipc.postMessage(JSON.stringify({
                            type: "dpop_proof",
                            proof: proof,
                        }));
                    } catch (e) {
                        window.ipc.postMessage(JSON.stringify({
                            type: "dpop_error",
                            error: e.message || String(e),
                        }));
                    }
                };

                console.log("[VPN Auth] WebView auth bridge loaded (with DPoP support)");
            })();
        "#;

        let login_url = format!("{}/app", config.app_url.trim_end_matches('/'));
        let proxy_clone = proxy.clone();

        let webview = WebViewBuilder::new()
            .with_url(&login_url)
            .with_initialization_script(init_script)
            .with_ipc_handler(move |msg| {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(msg.body()) {
                    match parsed["type"].as_str() {
                        Some("token") => {
                            if let Some(token) = parsed["token"].as_str() {
                                let is_initial = parsed["initial"].as_bool().unwrap_or(false);
                                set_latest_token(token);
                                if is_initial {
                                    tracing::info!("[WebView] Initial token received");
                                    let _ = initial_token_tx.try_send(token.to_string());
                                    let _ = proxy_clone.send_event("hide".to_string());
                                } else {
                                    tracing::info!("[WebView] Token refreshed");
                                }
                            }
                        }
                        Some("dpop_proof") => {
                            if let Some(proof) = parsed["proof"].as_str() {
                                tracing::debug!("[WebView] DPoP proof generated");
                                set_dpop_response(proof);
                            }
                        }
                        Some("dpop_error") => {
                            let err = parsed["error"].as_str().unwrap_or("unknown");
                            tracing::error!("[WebView] DPoP proof error: {err}");
                            set_dpop_response(&format!("ERROR:{err}"));
                        }
                        _ => {
                            tracing::debug!("[WebView] IPC: {}", msg.body());
                        }
                    }
                }
            })
            .with_devtools(cfg!(debug_assertions))
            .build_as_child(&window)
            .map_err(|e| format!("Failed to create webview: {e}"))?;

        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;

            match event {
                Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                } => {
                    *control_flow = ControlFlow::Exit;
                }
                Event::UserEvent(ref msg) if msg == "hide" => {
                    window.set_visible(false);
                }
                Event::UserEvent(ref msg) if msg == "close" => {
                    *control_flow = ControlFlow::Exit;
                }
                Event::UserEvent(ref msg) if msg.starts_with("dpop:") => {
                    // DPoP proof request from Rust → evaluate JS in webview
                    let json_str = &msg[5..];
                    if let Ok(req) = serde_json::from_str::<serde_json::Value>(json_str) {
                        let method = req["method"].as_str().unwrap_or("POST");
                        let url = req["url"].as_str().unwrap_or("");
                        let script = format!(
                            "window.__generateDPoPProof('{}', '{}')",
                            method.replace('\'', "\\'"),
                            url.replace('\'', "\\'"),
                        );
                        let _ = webview.evaluate_script(&script);
                    }
                }
                _ => {}
            }
        });
    }

    /// Async wrapper: spawns WebView, returns initial token.
    /// WebView stays alive hidden for token refresh + DPoP proof generation.
    pub async fn webview_oidc_login(app_url: &str) -> Result<String, String> {
        let config = WebViewAuthConfig {
            app_url: app_url.to_string(),
            ..Default::default()
        };

        let (token_tx, token_rx) = std::sync::mpsc::sync_channel::<String>(1);

        let _handle = std::thread::Builder::new()
            .name("webview-auth".into())
            .spawn(move || {
                if let Err(e) = open_auth_webview(config, token_tx) {
                    tracing::error!("[WebView] Auth window error: {e}");
                }
            })
            .map_err(|e| format!("Failed to spawn webview thread: {e}"))?;

        let token = tokio::task::spawn_blocking(move || {
            token_rx
                .recv_timeout(std::time::Duration::from_secs(300))
                .map_err(|e| format!("WebView auth timeout or window closed: {e}"))
        })
        .await
        .map_err(|e| format!("WebView task error: {e}"))??;

        tracing::info!("[WebView] Authentication successful");
        Ok(token)
    }

    pub fn webview_available() -> bool {
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("reg")
                .args([
                    "query",
                    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
                    "/v",
                    "pv",
                ])
                .output();
            return match output {
                Ok(out) => out.status.success(),
                Err(_) => false,
            };
        }

        #[cfg(target_os = "linux")]
        { return true; }

        #[cfg(target_os = "macos")]
        { return true; }

        #[allow(unreachable_code)]
        false
    }
}

// ── Stub when webview feature is not enabled ───────────────────────

#[cfg(not(feature = "webview"))]
mod imp {
    pub async fn webview_oidc_login(_app_url: &str) -> Result<String, String> {
        Err("WebView auth not compiled in (build with --features webview)".into())
    }

    pub fn webview_available() -> bool {
        false
    }
}

pub use imp::webview_available;
pub use imp::webview_oidc_login;
