//! First-run web-based setup UI.
//! If no config exists (no ssh-bridge.toml, no env vars, no data/tidecloak.json),
//! serves a configuration form, opens the browser, and waits for the user to submit.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Notify;

struct SetupState {
    done: Arc<Notify>,
}

// ── Config paths ────────────────────────────────────────────────

pub fn config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("KeyleSSH");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".keylessh");
        }
    }
    // Fallback: next to the executable
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_file_path() -> PathBuf {
    // If config already exists next to exe (portable mode), use that
    if let Ok(exe) = std::env::current_exe() {
        let beside_exe = exe.parent().unwrap_or(exe.as_ref()).join("ssh-bridge.toml");
        if beside_exe.exists() {
            return beside_exe;
        }
    }
    config_dir().join("ssh-bridge.toml")
}

/// Load saved config values from ssh-bridge.toml if it exists.
/// Returns (tidecloak_json_string, port) on success.
pub fn load_saved_config() -> Option<(String, u16)> {
    let path = config_file_path();
    let content = fs::read_to_string(&path).ok()?;

    let mut port = 8081u16;
    let mut tc_path = String::new();
    let mut tc_b64 = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"');
            match key {
                "port" => { port = val.parse().unwrap_or(8081); }
                "tidecloak_config_path" => { tc_path = val.to_string(); }
                "tidecloak_config_b64" => { tc_b64 = val.to_string(); }
                _ => {}
            }
        }
    }

    // Try loading tidecloak JSON
    if !tc_b64.is_empty() {
        let bytes = base64::engine::general_purpose::STANDARD.decode(&tc_b64).ok()?;
        let json = String::from_utf8(bytes).ok()?;
        return Some((json, port));
    }

    if !tc_path.is_empty() {
        // Resolve relative to config dir
        let tc = if PathBuf::from(&tc_path).is_absolute() {
            PathBuf::from(&tc_path)
        } else {
            let dir = config_file_path().parent().unwrap_or(&PathBuf::from(".")).to_path_buf();
            dir.join(&tc_path)
        };
        let json = fs::read_to_string(&tc).ok()?;
        return Some((json, port));
    }

    None
}

/// Check if first-run setup is needed, and if so, run it (blocking).
pub async fn run_setup_if_needed() {
    // Skip setup if env vars are set
    if std::env::var("client_adapter").is_ok()
        || std::env::var("TIDECLOAK_CONFIG_B64").is_ok()
    {
        return;
    }

    // Skip if data/tidecloak.json exists
    if PathBuf::from("data/tidecloak.json").exists()
        || PathBuf::from("../data/tidecloak.json").exists()
    {
        return;
    }

    // Skip if saved config exists and is loadable
    if load_saved_config().is_some() {
        return;
    }

    tracing::info!("No configuration found. Config dir: {}", config_dir().display());
    tracing::info!("Config file path: {}", config_file_path().display());
    tracing::info!("Starting setup wizard...");

    let done = Arc::new(Notify::new());
    let state = Arc::new(SetupState {
        done: done.clone(),
    });

    let app = Router::new()
        .route("/", get(serve_setup_page))
        .route("/save", post(handle_save))
        .with_state(state);

    let port = 7893u16;
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    let url = format!("http://localhost:{port}");
    tracing::info!("Open your browser to: {url}");

    open_browser(&url);

    let server = axum::serve(listener, app);
    tokio::select! {
        _ = server => {},
        _ = done.notified() => {
            tracing::info!("Configuration saved. Starting SSH Bridge...");
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
    use base64::Engine;

    let params: std::collections::HashMap<String, String> =
        serde_urlencoded::from_str(&body).unwrap_or_default();

    let get = |key: &str| params.get(key).cloned().unwrap_or_default();

    let tc_config_path = get("tidecloak_config_path");
    let tc_config_paste = get("tidecloak_config_paste");
    let listen_port = get("listen_port");

    // Must have at least one TideCloak source
    if tc_config_path.is_empty() && tc_config_paste.is_empty() {
        return (StatusCode::BAD_REQUEST, "TideCloak config is required").into_response();
    }

    // Build TOML
    let mut toml = String::new();
    toml.push_str("# SSH Bridge Configuration\n");
    toml.push_str("# Edit this file and restart to apply changes.\n\n");

    let lp = if listen_port.is_empty() { "8081" } else { &listen_port };
    toml.push_str(&format!("port = {lp}\n\n"));

    toml.push_str("# TideCloak\n");
    if !tc_config_paste.is_empty() {
        // Validate it's valid JSON
        if serde_json::from_str::<serde_json::Value>(&tc_config_paste).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid JSON in TideCloak config").into_response();
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(tc_config_paste.as_bytes());
        toml.push_str(&format!("tidecloak_config_b64 = \"{b64}\"\n"));
    } else if !tc_config_path.is_empty() {
        let escaped = tc_config_path.replace('\\', "\\\\").replace('"', "\\\"");
        toml.push_str(&format!("tidecloak_config_path = \"{escaped}\"\n"));
    }

    // Save
    let dir = config_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create {}: {e}", dir.display())).into_response();
    }
    let path = config_file_path();
    if let Err(e) = fs::write(&path, &toml) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save: {e}")).into_response();
    }
    tracing::info!("Saved config to {}", path.display());

    state.done.notify_one();

    (StatusCode::OK, format!("OK:{}", dir.display())).into_response()
}

const SETUP_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Bridge Setup</title>
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
  textarea { resize: vertical; min-height: 120px; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.8rem; }
  button { width: 100%; padding: 0.75rem; background: #0ea5e9; color: white;
           border: none; border-radius: 6px; font-size: 1rem; font-weight: 600;
           cursor: pointer; transition: background 0.2s; margin-top: 0.5rem; }
  button:hover { background: #0284c7; }
  button:disabled { background: #334155; cursor: not-allowed; }
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
  <h1>SSH Bridge Setup</h1>
  <p class="subtitle">Configure your SSH Bridge. Settings are saved to ssh-bridge.toml.</p>

  <form id="form">
    <div class="section">
      <h2>Server</h2>
      <label for="listen_port">Listen Port</label>
      <div class="hint">Port the bridge listens on for WebSocket connections</div>
      <input type="number" id="listen_port" name="listen_port" value="8081">
    </div>

    <div class="section">
      <h2>TideCloak Authentication</h2>
      <div class="tab-row">
        <div class="tab active" onclick="showTab('file')">Config File Path</div>
        <div class="tab" onclick="showTab('paste')">Paste JSON</div>
      </div>
      <div id="tab-file">
        <label for="tidecloak_config_path">Path to tidecloak.json</label>
        <div class="hint">Relative to config directory, or absolute path</div>
        <input type="text" id="tidecloak_config_path" name="tidecloak_config_path"
               placeholder="C:\path\to\tidecloak.json">
      </div>
      <div id="tab-paste" class="hidden">
        <label for="tidecloak_config_paste">TideCloak Config JSON</label>
        <div class="hint">Paste the contents of tidecloak.json here</div>
        <textarea id="tidecloak_config_paste" name="tidecloak_config_paste"
                  placeholder='{"realm": "...", "auth-server-url": "...", ...}'></textarea>
      </div>
    </div>

    <div id="error" class="error"></div>
    <button type="submit" id="submit-btn">Save &amp; Start</button>
  </form>

  <div id="success" class="success hidden">
    <h2>SSH Bridge Starting!</h2>
    <p>Configuration saved. You can close this tab.</p>
    <p id="config-info" style="display:none; margin-top:0.5rem; font-size:0.85rem; color:#64748b;">
      Config saved to: <code id="config-path" style="color:#38bdf8;"></code>
    </p>
  </div>
</div>

<script>
function showTab(tab) {
  document.getElementById('tab-file').classList.toggle('hidden', tab !== 'file');
  document.getElementById('tab-paste').classList.toggle('hidden', tab !== 'paste');
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  if (tab === 'file') {
    document.getElementById('tidecloak_config_paste').value = '';
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
    btn.textContent = 'Save & Start';
  }
});
</script>
</body>
</html>
"##;
