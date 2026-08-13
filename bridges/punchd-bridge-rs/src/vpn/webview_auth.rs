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

/// Get the latest *usable* token from the WebView.
///
/// The WebView's storage survives restarts, so the token found on startup is
/// frequently a leftover from the previous session. Returning an expired one
/// makes the caller skip login and then fail against the gateway, which looks
/// to the user like the app quitting without ever asking them to sign in.
pub fn get_latest_token() -> Option<String> {
    let token = token_store().lock().ok()?.clone()?;
    if token_is_usable(&token) {
        Some(token)
    } else {
        tracing::info!("[WebView] Cached token is expired — login required");
        None
    }
}

/// Get whatever token is cached, expired or not. Only for diagnostics.
pub fn peek_latest_token() -> Option<String> {
    token_store().lock().ok()?.clone()
}

fn set_latest_token(token: &str) {
    if let Ok(mut store) = token_store().lock() {
        *store = Some(token.to_string());
    }
}

fn clear_latest_token() {
    if let Ok(mut store) = token_store().lock() {
        *store = None;
    }
}

/// Seconds of headroom required on a token. A token about to expire is treated
/// as already expired so a connection isn't started with one that dies mid-handshake.
const TOKEN_MIN_REMAINING_SECS: u64 = 30;

/// Whether a JWT is well-formed and has enough life left to start a connection.
///
/// This is not signature verification — the gateway does that. It only prevents
/// the client from confidently presenting a token it can already see is stale.
pub fn token_is_usable(token: &str) -> bool {
    match token_expiry(token) {
        // No `exp` claim: nothing to judge it by, so let the gateway decide.
        Some(None) => true,
        Some(Some(exp)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            exp > now.saturating_add(TOKEN_MIN_REMAINING_SECS)
        }
        // Unparseable: not a JWT this client can use.
        None => false,
    }
}

/// Parse a JWT's `exp` claim. `None` if the token is malformed;
/// `Some(None)` if it parses but carries no `exp`.
fn token_expiry(token: &str) -> Option<Option<u64>> {
    use base64::Engine;

    let payload_b64 = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload_b64))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload_b64))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(claims.get("exp").and_then(|e| e.as_u64()))
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

/// Bring the login window back up and clear the stale session behind it.
///
/// The window is hidden after the first successful login and the app keeps
/// running, so without this there is no path back to a visible login prompt —
/// which is why "Refresh Token" appeared to do nothing once a token went stale.
#[cfg(feature = "webview")]
pub fn request_reauth() {
    clear_latest_token();
    send_to_webview("reauth");
}

#[cfg(not(feature = "webview"))]
pub fn request_reauth() {
    clear_latest_token();
}

/// Wait for the WebView to produce a usable token, polling the store.
///
/// Used when a login window already exists and has been asked to re-authenticate:
/// the initial-token channel belongs to the original login, so the token from a
/// second sign-in arrives through the store instead.
pub async fn wait_for_token(timeout: std::time::Duration) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(token) = get_latest_token() {
            return Ok(token);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("Timed out waiting for sign-in".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Whether a login window is currently available to be shown.
#[cfg(feature = "webview")]
pub fn webview_running() -> bool {
    EVENT_PROXY
        .get()
        .and_then(|m| m.lock().ok().map(|g| g.is_some()))
        .unwrap_or(false)
}

#[cfg(not(feature = "webview"))]
pub fn webview_running() -> bool {
    false
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
    use super::{set_latest_token, clear_latest_token, set_dpop_response, token_is_usable, EVENT_PROXY};

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
                let reportedAuthRequired = false;

                // Storage survives restarts, so the token present on load is
                // often left over from a previous session. Check it before
                // reporting it — otherwise the app skips login and then fails.
                function secondsRemaining(token) {
                    try {
                        const payload = JSON.parse(atob(
                            token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")
                        ));
                        if (!payload.exp) return Infinity;  // nothing to judge by
                        return payload.exp - Math.floor(Date.now() / 1000);
                    } catch (e) {
                        return -1;  // unparseable: treat as unusable
                    }
                }

                function isUsable(token) {
                    return !!token && secondsRemaining(token) > 30;
                }

                // ── Token polling ──
                function checkToken() {
                    const token = localStorage.getItem("access_token");

                    if (!isUsable(token)) {
                        // No usable token. Tell Rust once so it can show this
                        // window; the user is sitting in front of a login page.
                        if (!reportedAuthRequired) {
                            reportedAuthRequired = true;
                            lastToken = null;
                            window.ipc.postMessage(JSON.stringify({
                                type: "auth_required",
                                reason: token ? "expired" : "missing",
                            }));
                        }
                        return;
                    }

                    reportedAuthRequired = false;
                    if (token !== lastToken) {
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
                    if (e.key === "access_token") checkToken();
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

        // WebView2 data directory — must be writable (not Program Files)
        let data_dir = {
            #[cfg(target_os = "windows")]
            {
                std::path::PathBuf::from(r"C:\ProgramData\punchd-vpn\webview2")
            }
            #[cfg(not(target_os = "windows"))]
            {
                std::path::PathBuf::from("/var/lib/punchd-vpn/webview2")
            }
        };
        let _ = std::fs::create_dir_all(&data_dir);
        let mut web_context = wry::WebContext::new(Some(data_dir));

        let webview = WebViewBuilder::new_with_web_context(&mut web_context)
            .with_url(&login_url)
            .with_initialization_script(init_script)
            .with_ipc_handler(move |msg| {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(msg.body()) {
                    match parsed["type"].as_str() {
                        Some("token") => {
                            if let Some(token) = parsed["token"].as_str() {
                                let is_initial = parsed["initial"].as_bool().unwrap_or(false);
                                // Belt and braces: the page already filters expired
                                // tokens, but never hide the window on one.
                                if !token_is_usable(token) {
                                    tracing::warn!("[WebView] Ignoring expired token from page");
                                    let _ = proxy_clone.send_event("show".to_string());
                                    return;
                                }
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
                        Some("auth_required") => {
                            // The page has no usable token: either it never had
                            // one, or a refresh failed. Either way the user has to
                            // sign in, so the window must be in front of them.
                            let reason = parsed["reason"].as_str().unwrap_or("unknown");
                            tracing::info!("[WebView] Login required ({reason}) — showing window");
                            clear_latest_token();
                            let _ = proxy_clone.send_event("show".to_string());
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
            .build(&window)
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
                Event::UserEvent(ref msg) if msg == "show" => {
                    window.set_visible(true);
                    window.set_focus();
                }
                Event::UserEvent(ref msg) if msg == "reauth" => {
                    // Drop the stale session and land back on the login page,
                    // rather than showing a window still holding a dead token.
                    let _ = webview.evaluate_script(
                        "try { localStorage.removeItem('access_token'); } catch (e) {}",
                    );
                    let _ = webview.load_url(&login_url);
                    window.set_visible(true);
                    window.set_focus();
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

#[cfg(test)]
mod token_tests {
    use super::*;
    use base64::Engine;

    fn jwt(claims: serde_json::Value) -> String {
        let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!(
            "{}.{}.{}",
            b64(br#"{"alg":"EdDSA","typ":"JWT"}"#),
            b64(claims.to_string().as_bytes()),
            b64(b"not-a-real-signature"),
        )
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn accepts_a_token_with_life_left() {
        assert!(token_is_usable(&jwt(serde_json::json!({ "exp": now() + 3600 }))));
    }

    #[test]
    fn rejects_an_expired_token() {
        // The startup bug: a token left in WebView storage by the previous
        // session must not be accepted as a reason to skip login.
        assert!(!token_is_usable(&jwt(serde_json::json!({ "exp": now() - 1 }))));
        assert!(!token_is_usable(&jwt(serde_json::json!({ "exp": now() - 86_400 }))));
    }

    #[test]
    fn rejects_a_token_about_to_expire() {
        // Would die mid-handshake; treat as already gone.
        assert!(!token_is_usable(&jwt(serde_json::json!({ "exp": now() + 5 }))));
    }

    #[test]
    fn accepts_a_token_past_the_leeway() {
        assert!(token_is_usable(&jwt(serde_json::json!({ "exp": now() + 120 }))));
    }

    #[test]
    fn accepts_a_token_with_no_expiry_claim() {
        // Nothing to judge it by — let the gateway be the authority.
        assert!(token_is_usable(&jwt(serde_json::json!({ "sub": "user" }))));
    }

    #[test]
    fn rejects_malformed_tokens() {
        assert!(!token_is_usable(""));
        assert!(!token_is_usable("not-a-jwt"));
        assert!(!token_is_usable("only.two"));
        assert!(!token_is_usable("header.!!!not-base64!!!.sig"));
        assert!(!token_is_usable("header.bm90LWpzb24.sig"));
    }

    #[test]
    fn get_latest_token_hides_an_expired_one() {
        set_latest_token(&jwt(serde_json::json!({ "exp": now() - 1 })));
        assert!(peek_latest_token().is_some(), "still cached for diagnostics");
        assert!(get_latest_token().is_none(), "but not offered to the caller");

        let good = jwt(serde_json::json!({ "exp": now() + 3600 }));
        set_latest_token(&good);
        assert_eq!(get_latest_token().as_deref(), Some(good.as_str()));

        clear_latest_token();
        assert!(get_latest_token().is_none());
    }
}
