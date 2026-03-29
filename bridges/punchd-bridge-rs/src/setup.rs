//! First-run web-based setup UI.
//! If no gateway.toml exists, serves a configuration form on port 7892,
//! opens the browser, and waits for the user to submit the form.

use std::fs;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Notify;

use crate::config::{config_dir, config_file_path};

struct SetupState {
    done: Arc<Notify>,
}

/// Check if first-run setup is needed, and if so, run it (blocking).
pub async fn run_setup_if_needed() {
    let path = config_file_path();
    let has_config = path.exists();
    let has_env = std::env::var("STUN_SERVER_URL").is_ok() || std::env::var("BACKENDS").is_ok();

    if has_config || has_env {
        return;
    }

    tracing::info!("No gateway.toml found. Starting setup wizard...");

    let done = Arc::new(Notify::new());
    let state = Arc::new(SetupState {
        done: done.clone(),
    });

    let app = Router::new()
        .route("/", get(serve_setup_page))
        .route("/save", post(handle_save))
        .with_state(state);

    let port = 7892u16;
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    let url = format!("http://localhost:{port}");
    tracing::info!("Open your browser to: {url}");

    // Try to open browser automatically
    open_browser(&url);

    // Serve until config is saved
    let server = axum::serve(listener, app);
    tokio::select! {
        _ = server => {},
        _ = done.notified() => {
            tracing::info!("Configuration saved. Starting gateway...");
        }
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

async fn serve_setup_page() -> Html<&'static str> {
    Html(SETUP_HTML)
}

async fn handle_save(
    State(state): State<Arc<SetupState>>,
    body: String,
) -> impl IntoResponse {
    // Parse form data
    let params: std::collections::HashMap<String, String> =
        serde_urlencoded::from_str(&body).unwrap_or_default();

    let get = |key: &str| params.get(key).cloned().unwrap_or_default();

    let gateway_id = get("gateway_id");
    let stun_server_url = get("stun_server_url");
    let api_secret = get("api_secret");
    let backends = get("backends");
    let tc_config_path = get("tidecloak_config_path");
    let tc_config_b64 = get("tidecloak_config_b64");
    let ice_servers = get("ice_servers");
    let turn_server = get("turn_server");
    let turn_secret = get("turn_secret");
    let listen_port = get("listen_port");
    let health_port = get("health_port");
    let auth_server_public_url = get("auth_server_public_url");

    // Validate required fields
    if stun_server_url.is_empty() || api_secret.is_empty() || backends.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing required fields").into_response();
    }
    if tc_config_path.is_empty() && tc_config_b64.is_empty() {
        return (StatusCode::BAD_REQUEST, "TideCloak config is required").into_response();
    }

    // Build TOML
    let mut toml = String::new();
    toml.push_str("# Punchd Gateway Configuration\n");
    toml.push_str("# Edit this file and restart the gateway to apply changes.\n\n");

    write_field(&mut toml, "gateway_id", &gateway_id);
    toml.push('\n');
    toml.push_str("# STUN/TURN Server\n");
    write_field(&mut toml, "stun_server_url", &stun_server_url);
    write_field(&mut toml, "api_secret", &api_secret);
    if !ice_servers.is_empty() {
        write_field(&mut toml, "ice_servers", &ice_servers);
    }
    if !turn_server.is_empty() {
        write_field(&mut toml, "turn_server", &turn_server);
    }
    if !turn_secret.is_empty() {
        write_field(&mut toml, "turn_secret", &turn_secret);
    }
    toml.push('\n');
    toml.push_str("# Backends\n");
    write_field(&mut toml, "backends", &backends);
    toml.push('\n');
    toml.push_str("# TideCloak\n");
    if !tc_config_path.is_empty() {
        write_field(&mut toml, "tidecloak_config_path", &tc_config_path);
    }
    if !tc_config_b64.is_empty() {
        write_field(&mut toml, "tidecloak_config_b64", &tc_config_b64);
    }
    if !auth_server_public_url.is_empty() {
        write_field(&mut toml, "auth_server_public_url", &auth_server_public_url);
    }
    toml.push('\n');
    toml.push_str("# Server\n");
    let lp = if listen_port.is_empty() { "7891" } else { &listen_port };
    let hp = if health_port.is_empty() { "7892" } else { &health_port };
    toml.push_str(&format!("listen_port = {lp}\n"));
    toml.push_str(&format!("health_port = {hp}\n"));
    toml.push_str("https = true\n");
    toml.push_str("tls_hostname = \"localhost\"\n");

    // Save — create config directory if needed
    let dir = config_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create {}: {e}", dir.display())).into_response();
    }
    let path = config_file_path();
    if let Err(e) = fs::write(&path, &toml) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save: {e}")).into_response();
    }
    tracing::info!("Saved config to {}", path.display());

    // Signal done
    state.done.notify_one();

    (StatusCode::OK, format!("OK:{}", dir.display())).into_response()
}

fn write_field(s: &mut String, key: &str, val: &str) {
    let escaped = val.replace('\\', "\\\\").replace('"', "\\\"");
    s.push_str(&format!("{key} = \"{escaped}\"\n"));
}

const SETUP_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Punchd Gateway Setup</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 2rem; }
  .container { max-width: 640px; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin-bottom: 0.25rem; color: #38bdf8; }
  .subtitle { color: #94a3b8; margin-bottom: 2rem; font-size: 0.9rem; }
  .section { margin-bottom: 1.5rem; }
  .section h2 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;
                 color: #64748b; margin-bottom: 0.75rem; padding-bottom: 0.5rem;
                 border-bottom: 1px solid #1e293b; }
  label { display: block; font-size: 0.85rem; color: #cbd5e1; margin-bottom: 0.25rem; }
  .hint { font-size: 0.75rem; color: #64748b; margin-bottom: 0.5rem; }
  input, textarea { width: 100%; padding: 0.5rem 0.75rem; background: #1e293b;
                    border: 1px solid #334155; border-radius: 6px; color: #e2e8f0;
                    font-size: 0.9rem; font-family: inherit; margin-bottom: 1rem;
                    outline: none; transition: border-color 0.2s; }
  input:focus, textarea:focus { border-color: #38bdf8; }
  input::placeholder, textarea::placeholder { color: #475569; }
  textarea { resize: vertical; min-height: 60px; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.8rem; }
  .row { display: flex; gap: 1rem; }
  .row > div { flex: 1; }
  button { width: 100%; padding: 0.75rem; background: #0ea5e9; color: white;
           border: none; border-radius: 6px; font-size: 1rem; font-weight: 600;
           cursor: pointer; transition: background 0.2s; margin-top: 0.5rem; }
  button:hover { background: #0284c7; }
  button:disabled { background: #334155; cursor: not-allowed; }
  .required::after { content: ' *'; color: #f87171; }
  .success { text-align: center; padding: 3rem 1rem; }
  .success h2 { color: #4ade80; font-size: 1.5rem; margin-bottom: 0.5rem; }
  .success p { color: #94a3b8; }
  .error { color: #f87171; font-size: 0.85rem; margin-bottom: 1rem; display: none; }
  .tab-row { display: flex; gap: 0; margin-bottom: 1rem; }
  .tab { padding: 0.4rem 1rem; background: #1e293b; border: 1px solid #334155;
         cursor: pointer; font-size: 0.8rem; color: #94a3b8; }
  .tab:first-child { border-radius: 6px 0 0 6px; }
  .tab:last-child { border-radius: 0 6px 6px 0; }
  .tab.active { background: #334155; color: #e2e8f0; }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="container">
  <h1>Punchd Gateway Setup</h1>
  <p class="subtitle">Configure your gateway. Settings are saved to gateway.toml.</p>

  <form id="form">
    <div class="section">
      <h2>Gateway</h2>
      <label for="gateway_id">Gateway ID</label>
      <div class="hint">Unique name for this gateway instance</div>
      <input type="text" id="gateway_id" name="gateway_id" placeholder="my-gateway">
    </div>

    <div class="section">
      <h2>STUN / TURN Server</h2>
      <label class="required" for="stun_server_url">STUN Server URL</label>
      <input type="text" id="stun_server_url" name="stun_server_url" required
             placeholder="wss://stun.example.com:9090">

      <label class="required" for="api_secret">API Secret</label>
      <div class="hint">Shared secret for authenticating with the STUN server</div>
      <input type="password" id="api_secret" name="api_secret" required
             placeholder="Enter API secret">

      <label for="ice_servers">ICE Servers</label>
      <div class="hint">Comma-separated. Leave blank to auto-detect from STUN URL.</div>
      <input type="text" id="ice_servers" name="ice_servers"
             placeholder="stun:203.0.113.1:3478">

      <label for="turn_server">TURN Server</label>
      <input type="text" id="turn_server" name="turn_server"
             placeholder="turn:203.0.113.1:3478">

      <label for="turn_secret">TURN Secret</label>
      <input type="password" id="turn_secret" name="turn_secret"
             placeholder="Enter TURN secret (optional)">
    </div>

    <div class="section">
      <h2>Backends</h2>
      <label class="required" for="backends">Backend Services</label>
      <div class="hint">
        Format: name=url (comma-separated). Flags: ;noauth ;stripauth<br>
        HTTP: myapp=http://localhost:3000<br>
        RDP: mypc=rdp://192.168.1.100:3389
      </div>
      <textarea id="backends" name="backends" required
                placeholder="myapp=http://localhost:3000,mypc=rdp://192.168.1.100:3389"></textarea>
    </div>

    <div class="section">
      <h2>TideCloak Authentication</h2>
      <div class="tab-row">
        <div class="tab active" onclick="showTab('file')">Config File</div>
        <div class="tab" onclick="showTab('b64')">Base64 / Paste</div>
      </div>
      <div id="tab-file">
        <label for="tidecloak_config_path">Path to tidecloak.json</label>
        <div class="hint">Relative to the executable, or absolute path</div>
        <input type="text" id="tidecloak_config_path" name="tidecloak_config_path"
               value="tidecloak.json" placeholder="tidecloak.json">
      </div>
      <div id="tab-b64" class="hidden">
        <label for="tidecloak_config_b64">Base64-encoded TideCloak config</label>
        <div class="hint">Paste the base64 string (from TIDECLOAK_CONFIG_B64)</div>
        <textarea id="tidecloak_config_b64" name="tidecloak_config_b64"
                  placeholder="eyJyZWFsbSI6..."></textarea>
      </div>
      <label for="auth_server_public_url">Auth Server Public URL</label>
      <div class="hint">Public URL of TideCloak if different from auth-server-url in config (e.g. https://staging.dauth.me)</div>
      <input type="text" id="auth_server_public_url" name="auth_server_public_url"
             placeholder="https://staging.dauth.me">
    </div>

    <div class="section">
      <h2>Server</h2>
      <div class="row">
        <div>
          <label for="listen_port">Listen Port</label>
          <input type="number" id="listen_port" name="listen_port" value="7891">
        </div>
        <div>
          <label for="health_port">Health Port</label>
          <input type="number" id="health_port" name="health_port" value="7892">
        </div>
      </div>
    </div>

    <div id="error" class="error"></div>
    <button type="submit" id="submit-btn">Save &amp; Start Gateway</button>
  </form>

  <div id="success" class="success hidden">
    <h2>Gateway Starting!</h2>
    <p>Configuration saved. You can close this tab.</p>
    <p id="config-info" style="display:none; margin-top:0.5rem; font-size:0.85rem; color:#64748b;">
      Config dir: <code id="config-path" style="color:#38bdf8;"></code><br>
      Place <code>tidecloak.json</code> in this folder if using a file.
    </p>
  </div>
</div>

<script>
function showTab(tab) {
  document.getElementById('tab-file').classList.toggle('hidden', tab !== 'file');
  document.getElementById('tab-b64').classList.toggle('hidden', tab !== 'b64');
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  // Clear the inactive tab's value
  if (tab === 'file') {
    document.getElementById('tidecloak_config_b64').value = '';
  } else {
    document.getElementById('tidecloak_config_path').value = '';
  }
}

document.getElementById('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  const errEl = document.getElementById('error');
  btn.disabled = true;
  btn.textContent = 'Saving...';
  errEl.style.display = 'none';

  const form = new FormData(e.target);
  const body = new URLSearchParams(form).toString();

  try {
    const res = await fetch('/save', { method: 'POST', body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || 'Save failed');
    }
    const text = await res.text();
    const configDir = text.startsWith('OK:') ? text.slice(3) : '';
    document.getElementById('form').classList.add('hidden');
    const successEl = document.getElementById('success');
    if (configDir) {
      document.getElementById('config-path').textContent = configDir;
      document.getElementById('config-info').style.display = 'block';
    }
    successEl.classList.remove('hidden');
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Save & Start Gateway';
  }
});
</script>
</body>
</html>
"##;
