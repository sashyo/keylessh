///! Bridge-side VPN session management.
///!
///! Handles `vpn_open` / `vpn_close` control messages from peers,
///! allocates IP addresses from a pool, creates a TUN device,
///! and shuttles IP packets between the TUN and the WebRTC bulk DataChannel.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::auth::tidecloak::TidecloakAuth;
use super::tun_device::{TunConfig, TunDevice};

const VPN_TUNNEL_MAGIC: u8 = 0x04;
const VPN_MTU: u16 = 1400;

/// A firewall rule parsed from a VPN role.
/// Format: `vpn:<gateway>:<allow|deny>:<network>/<prefix>:<ports>:<priority>`
/// Priority is optional (defaults to 0). Higher priority rules are evaluated first.
#[derive(Clone, Debug)]
pub struct FirewallRule {
    pub action: FirewallAction,
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub ports: PortMatch,
    pub priority: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum FirewallAction {
    Allow,
    Deny,
}

#[derive(Clone, Debug)]
pub enum PortMatch {
    Any,
    Specific(Vec<u16>),
}

impl FirewallRule {
    /// Parse from role string: `vpn:GatewayId:allow:192.168.0.0/24:80,443:10`
    pub fn parse(role: &str, gateway_id: &str) -> Option<Self> {
        let prefix_str = format!("vpn:{gateway_id}:");
        if !role.starts_with(&prefix_str) {
            return None;
        }
        let rest = &role[prefix_str.len()..];
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() < 2 {
            return None;
        }

        let action = match parts[0] {
            "allow" => FirewallAction::Allow,
            "deny" => FirewallAction::Deny,
            _ => return None,
        };

        // Parse network/prefix
        let net_parts: Vec<&str> = parts[1].split('/').collect();
        let network: Ipv4Addr = net_parts[0].parse().ok()?;
        let prefix: u8 = net_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(32);

        // Parse ports
        let ports = if parts.len() < 3 || parts[2] == "*" {
            PortMatch::Any
        } else {
            let port_list: Vec<u16> = parts[2]
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();
            if port_list.is_empty() {
                PortMatch::Any
            } else {
                PortMatch::Specific(port_list)
            }
        };

        // Parse priority (optional, defaults to 0)
        let priority = if parts.len() >= 4 {
            parts[3].parse::<i32>().unwrap_or(0)
        } else {
            0
        };

        Some(FirewallRule {
            action,
            network,
            prefix,
            ports,
            priority,
        })
    }

    /// Check if a destination IP and port match this rule.
    pub fn matches(&self, dst_ip: Ipv4Addr, dst_port: u16) -> bool {
        let mask = if self.prefix == 0 { 0u32 } else { !0u32 << (32 - self.prefix) };
        let net = u32::from(self.network) & mask;
        let dst = u32::from(dst_ip) & mask;
        if net != dst {
            return false;
        }
        match &self.ports {
            PortMatch::Any => true,
            PortMatch::Specific(ports) => ports.contains(&dst_port),
        }
    }
}

/// Per-session firewall: list of rules extracted from the user's roles.
/// If no rules are present (just `vpn:GatewayId`), all traffic is allowed.
/// If rules exist, default is deny — only explicitly allowed traffic passes.
/// Uses a decision cache for O(1) lookups on repeated destinations.
#[derive(Clone, Debug)]
pub struct SessionFirewall {
    pub rules: Vec<FirewallRule>,
    /// Cache of recent firewall decisions: (ip_u32, port) -> allowed
    decision_cache: std::collections::HashMap<(u32, u16), bool>,
    /// Tracks recently blocked destinations to avoid spamming notifications.
    blocked_cache: std::collections::HashSet<String>,
    /// Channel to send block notifications to the client via control channel.
    pub block_notify_tx: Option<mpsc::UnboundedSender<(Ipv4Addr, u16)>>,
}

impl SessionFirewall {
    pub fn new(mut rules: Vec<FirewallRule>) -> Self {
        // Sort by priority descending — highest priority evaluated first
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Self {
            rules,
            decision_cache: std::collections::HashMap::with_capacity(64),
            blocked_cache: std::collections::HashSet::new(),
            block_notify_tx: None,
        }
    }

    /// Check if a packet to dst_ip:dst_port is allowed.
    /// Uses a cache for O(1) lookups on repeated destinations.
    /// Rules are evaluated highest-priority-first. First matching rule wins.
    /// If no rules exist, all traffic is allowed.
    /// If rules exist but none match, default is deny.
    pub fn is_allowed(&mut self, dst_ip: Ipv4Addr, dst_port: u16) -> bool {
        if self.rules.is_empty() {
            return true;
        }

        let key = (u32::from(dst_ip), dst_port);
        if let Some(&cached) = self.decision_cache.get(&key) {
            return cached;
        }

        let result = self.evaluate(dst_ip, dst_port);

        // Cap cache size to prevent unbounded growth
        if self.decision_cache.len() >= 4096 {
            self.decision_cache.clear();
        }
        self.decision_cache.insert(key, result);

        result
    }

    fn evaluate(&self, dst_ip: Ipv4Addr, dst_port: u16) -> bool {
        for rule in &self.rules {
            if rule.matches(dst_ip, dst_port) {
                return rule.action == FirewallAction::Allow;
            }
        }
        false
    }

    /// Log a blocked packet, rate-limited per destination.
    /// Sends a notification to the client on first block per destination.
    pub fn log_blocked(&mut self, dst_ip: Ipv4Addr, dst_port: u16) {
        let key = format!("{}:{}", dst_ip, dst_port);
        if self.blocked_cache.insert(key) {
            // First time seeing this destination — log and notify
            tracing::warn!("[VPN] BLOCKED: -> {}:{} (firewall policy)", dst_ip, dst_port);
            if let Some(ref tx) = self.block_notify_tx {
                let _ = tx.send((dst_ip, dst_port));
            }
        }
    }
}

/// Extract destination port from an IPv4 packet (TCP or UDP).
pub fn extract_dst_port(packet: &[u8]) -> u16 {
    if packet.len() < 24 {
        return 0;
    }
    let proto = packet[9];
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 4 {
        return 0;
    }
    match proto {
        6 | 17 => {
            // TCP or UDP: dst port at offset ihl+2..ihl+4
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]])
        }
        1 => 0, // ICMP has no port — always match
        _ => 0,
    }
}

/// A single VPN session associated with a peer.
pub struct VpnSession {
    pub id: String,
    pub client_ip: Ipv4Addr,
    /// Send IP packets to be written to the TUN device.
    pub tun_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Receive IP packets from the TUN device destined for this client.
    pub route_rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Signal shutdown of the TUN read/write tasks.
    pub shutdown: Option<oneshot::Sender<()>>,
    /// Per-session firewall rules from the user's roles.
    pub firewall: SessionFirewall,
    /// Receives block notifications to send to the client.
    pub block_rx: Option<mpsc::UnboundedReceiver<(Ipv4Addr, u16)>>,
}

/// Simple IP address pool for VPN clients.
pub struct IpPool {
    /// Gateway IP (e.g., 10.66.0.1)
    pub gateway_ip: Ipv4Addr,
    /// Subnet mask
    pub netmask: Ipv4Addr,
    /// Next IP octet to try
    next: u8,
    /// Currently allocated IPs
    allocated: HashSet<Ipv4Addr>,
}

impl IpPool {
    pub fn new(subnet: &str) -> Self {
        // Parse "10.66.0.0/24" style
        let parts: Vec<&str> = subnet.split('/').collect();
        let base: Ipv4Addr = parts[0].parse().unwrap_or(Ipv4Addr::new(10, 0, 0, 0));
        let prefix: u8 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(24);

        let octets = base.octets();
        let gateway_ip = Ipv4Addr::new(octets[0], octets[1], octets[2], 1);

        let netmask = match prefix {
            24 => Ipv4Addr::new(255, 255, 255, 0),
            16 => Ipv4Addr::new(255, 255, 0, 0),
            _ => Ipv4Addr::new(255, 255, 255, 0),
        };

        Self {
            gateway_ip,
            netmask,
            next: 2,
            allocated: HashSet::new(),
        }
    }

    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        let base = self.gateway_ip.octets();
        for _ in 0..253 {
            let ip = Ipv4Addr::new(base[0], base[1], base[2], self.next);
            self.next = if self.next >= 254 { 2 } else { self.next + 1 };
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Some(ip);
            }
        }
        None
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        self.allocated.remove(&ip);
    }
}

/// Shared VPN state across all peers on the bridge.
pub struct VpnState {
    pub pool: IpPool,
    /// Map from client IP -> bulk channel sender for routing TUN reads back to the right peer.
    pub routes: HashMap<Ipv4Addr, mpsc::UnboundedSender<Vec<u8>>>,
    pub enabled: bool,
    tun_started: bool,
}

impl VpnState {
    pub fn new(subnet: &str, enabled: bool) -> Self {
        Self {
            pool: IpPool::new(subnet),
            routes: HashMap::new(),
            enabled,
            tun_started: false,
        }
    }
}

/// Handle a `vpn_open` message from a peer.
///
/// Called from peer_handler.rs when the control channel receives:
/// `{ "type": "vpn_open", "id": "<uuid>" }`
///
/// Returns the VpnSession to be stored in PeerState.
pub async fn handle_vpn_open(
    vpn_state: Arc<Mutex<VpnState>>,
    id: String,
    token: Option<&str>,
    auth: Option<&Arc<TidecloakAuth>>,
    gateway_id: &str,
) -> Result<VpnSession, String> {
    // Verify JWT token and check role
    let required_role = format!("vpn:{gateway_id}");
    let mut firewall_rules: Vec<FirewallRule> = Vec::new();

    match (token, auth) {
        (Some(tok), Some(auth)) => {
            match auth.verify_token(tok).await {
                Some(payload) => {
                    let user = payload.sub.as_deref().unwrap_or("unknown");

                    // Collect all roles: realm_access.roles + resource_access.*.roles
                    let mut all_roles: Vec<String> = Vec::new();
                    if let Some(ref ra) = payload.realm_access {
                        all_roles.extend(ra.roles.clone());
                    }
                    if let Some(ref ra) = payload.resource_access {
                        if let Some(obj) = ra.as_object() {
                            for (_client, access) in obj {
                                if let Some(roles) = access.get("roles").and_then(|r| r.as_array()) {
                                    for role in roles {
                                        if let Some(r) = role.as_str() {
                                            all_roles.push(r.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !all_roles.iter().any(|r| r == &required_role || r.starts_with(&format!("{required_role}:"))) {
                        tracing::warn!(
                            "[VPN] User {} lacks role '{}'. Has: {:?}",
                            user, required_role, all_roles
                        );
                        return Err(format!("Access denied: role '{}' required", required_role));
                    }

                    // Parse firewall rules from roles
                    let fw_rules: Vec<FirewallRule> = all_roles
                        .iter()
                        .filter_map(|r| FirewallRule::parse(r, gateway_id))
                        .collect();

                    if fw_rules.is_empty() {
                        tracing::info!("[VPN] Token verified for user: {} (role: {}, no firewall rules — allow all)", user, required_role);
                    } else {
                        tracing::info!("[VPN] Token verified for user: {} (role: {}, {} firewall rules)", user, required_role, fw_rules.len());
                        for rule in &fw_rules {
                            tracing::info!("[VPN]   {:?} {}/{} ports:{:?}", rule.action, rule.network, rule.prefix, rule.ports);
                        }
                    }

                    // Store firewall for the session
                    firewall_rules = fw_rules;
                }
                None => {
                    return Err("Invalid or expired token".into());
                }
            }
        }
        (None, Some(_)) => {
            return Err("Token required for VPN access".into());
        }
        _ => {
            tracing::warn!("[VPN] No auth configured, allowing VPN without token");
        }
    }

    let mut vs = vpn_state.lock().await;

    if !vs.enabled {
        return Err("VPN is not enabled on this gateway".into());
    }

    let client_ip = vs.pool.allocate().ok_or("IP pool exhausted")?;
    let gateway_ip = vs.pool.gateway_ip;
    let netmask = vs.pool.netmask;

    // Channel for sending packets from the peer's bulk channel to the TUN writer
    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Channel for sending packets from the TUN reader back to the peer's bulk channel
    let (route_tx, route_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    vs.routes.insert(client_ip, route_tx);

    tracing::info!("[VPN] IP pool allocated {} for session {}", client_ip, id);

    // Start the shared TUN device if not already running
    if !vs.tun_started {
        vs.tun_started = true;
        let tun_name = "punchd-vpn0".to_string();
        let vpn_state_tun = vpn_state.clone();

        tokio::spawn(async move {
            if let Err(e) = run_tun_device(tun_name, gateway_ip, netmask, vpn_state_tun).await {
                tracing::error!("[VPN] TUN device error: {}", e);
            }
        });
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    drop(vs);

    // Spawn task: write packets from peer to TUN device
    // The TUN writer reads from tun_rx and routes to the shared TUN device
    let vpn_state_write = vpn_state.clone();
    let cip = client_ip;
    let (block_tx, block_rx) = mpsc::unbounded_channel::<(Ipv4Addr, u16)>();
    let mut firewall = SessionFirewall::new(firewall_rules.clone());
    firewall.block_notify_tx = Some(block_tx);
    tokio::spawn(async move {
        let mut shutdown = shutdown_rx;
        loop {
            tokio::select! {
                packet = tun_rx.recv() => {
                    match packet {
                        Some(data) => {
                            // Drop non-IPv4 packets
                            if data.is_empty() || (data[0] >> 4) != 4 {
                                continue;
                            }
                            if data.len() >= 20 {
                                // Only parse headers and check firewall if rules exist
                                if !firewall.rules.is_empty() {
                                    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                                    let dst_port = extract_dst_port(&data);
                                    if !firewall.is_allowed(dst, dst_port) {
                                        firewall.log_blocked(dst, dst_port);
                                        continue;
                                    }
                                }
                            }
                            match TUN_WRITE_TX.get() {
                                Some(tx) => { let _ = tx.send(data); }
                                None => { tracing::warn!("[VPN] TUN write channel not ready, dropping packet"); }
                            }
                        }
                        None => break,
                    }
                }
                _ = &mut shutdown => {
                    break;
                }
            }
        }
        // Clean up
        let mut vs = vpn_state_write.lock().await;
        vs.pool.release(cip);
        vs.routes.remove(&cip);
        tracing::info!("[VPN] Session closed, released IP {}", cip);
    });

    tracing::info!(
        "[VPN] Session opened: client_ip={}, gateway_ip={}, id={}",
        client_ip,
        gateway_ip,
        id
    );

    Ok(VpnSession {
        id,
        client_ip,
        tun_tx,
        route_rx: Some(route_rx),
        shutdown: Some(shutdown_tx),
        firewall: SessionFirewall::new(firewall_rules),
        block_rx: Some(block_rx),
    })
}

/// Get VPN session info for the `vpn_opened` response.
pub fn vpn_opened_response(session: &VpnSession, gateway_ip: Ipv4Addr, netmask: Ipv4Addr) -> serde_json::Value {
    let lan_routes = detect_lan_subnets(gateway_ip);
    json!({
        "type": "vpn_opened",
        "id": session.id,
        "clientIp": session.client_ip.to_string(),
        "serverIp": gateway_ip.to_string(),
        "netmask": netmask.to_string(),
        "mtu": VPN_MTU,
        "routes": lan_routes,
    })
}

/// Detect LAN subnets on the gateway by inspecting network interfaces.
/// Returns a list of "subnet/prefix" strings (e.g., ["192.168.0.0/24"]).
/// Excludes loopback, link-local, the VPN subnet itself, and common virtual adapters.
fn detect_lan_subnets(vpn_gateway_ip: Ipv4Addr) -> Vec<String> {
    let mut subnets = Vec::new();

    // Use OS commands to enumerate interfaces
    #[cfg(target_os = "windows")]
    {
        // Parse `netsh interface ipv4 show addresses` output
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses"])
            .output();
        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut current_ip: Option<Ipv4Addr> = None;
            let mut current_mask: Option<Ipv4Addr> = None;

            for line in text.lines() {
                let line = line.trim();
                if line.starts_with("IP Address:") || line.starts_with("IP") && line.contains("Address") {
                    if let Some(ip_str) = line.split_whitespace().last() {
                        current_ip = ip_str.parse().ok();
                    }
                } else if line.starts_with("Subnet Prefix:") || line.contains("Subnet") && line.contains("mask") {
                    // Try to extract mask from "Subnet Prefix: x.x.x.x/NN (mask x.x.x.x)"
                    if let Some(mask_part) = line.split("mask").nth(1) {
                        let mask_str = mask_part.trim().trim_end_matches(')').trim();
                        current_mask = mask_str.parse().ok();
                    }
                }

                if let (Some(ip), Some(mask)) = (current_ip, current_mask) {
                    let o = ip.octets();
                    let m = mask.octets();
                    let net = Ipv4Addr::new(o[0] & m[0], o[1] & m[1], o[2] & m[2], o[3] & m[3]);
                    let prefix: u32 = m.iter().map(|b| b.count_ones()).sum();

                    // Skip loopback, link-local, VPN subnet, and unroutable
                    let skip = ip.is_loopback()
                        || o[0] == 169 && o[1] == 254  // link-local
                        || o[0] == 100 && o[1] == 64 && o[2] == 0  // VPN subnet 10.66.0.x
                        || ip == vpn_gateway_ip
                        || o[0] == 0;

                    if !skip && prefix > 0 && prefix <= 30 {
                        let subnet = format!("{}/{}", net, prefix);
                        if !subnets.contains(&subnet) {
                            subnets.push(subnet);
                        }
                    }
                    current_ip = None;
                    current_mask = None;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ip")
            .args(["-4", "-o", "addr", "show"])
            .output();
        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                // Format: "2: eth0 inet 192.168.1.5/24 brd ..."
                if let Some(inet_part) = line.split("inet ").nth(1) {
                    if let Some(cidr) = inet_part.split_whitespace().next() {
                        let parts: Vec<&str> = cidr.split('/').collect();
                        if parts.len() == 2 {
                            if let (Ok(ip), Ok(prefix)) = (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<u32>()) {
                                let o = ip.octets();
                                let mask_bits = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
                                let m = mask_bits.to_be_bytes();
                                let net = Ipv4Addr::new(o[0] & m[0], o[1] & m[1], o[2] & m[2], o[3] & m[3]);

                                let skip = ip.is_loopback()
                                    || o[0] == 169 && o[1] == 254
                                    || o[0] == 10 && o[1] == 0 && o[2] == 0
                                    || ip == vpn_gateway_ip
                                    || o[0] == 0;

                                if !skip && prefix > 0 && prefix <= 30 {
                                    let subnet = format!("{}/{}", net, prefix);
                                    if !subnets.contains(&subnet) {
                                        subnets.push(subnet);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::info!("[VPN] Detected LAN subnets: {:?}", subnets);
    subnets
}

// ── Global TUN write channel ────────────────────────────────────────
// Packets from all VPN peers are funneled into this channel to be
// written to the single shared TUN device.

use std::sync::OnceLock;
static TUN_WRITE_TX: OnceLock<mpsc::UnboundedSender<Vec<u8>>> = OnceLock::new();

/// Run the shared TUN device. Reads IP packets from TUN and routes
/// them to the correct peer based on destination IP. Also writes
/// packets from peers into the TUN device.
async fn run_tun_device(
    name: String,
    gateway_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    vpn_state: Arc<Mutex<VpnState>>,
) -> Result<(), String> {
    let config = TunConfig {
        name,
        address: gateway_ip,
        netmask,
        mtu: VPN_MTU,
    };

    let mut tun = TunDevice::create(&config)
        .map_err(|e| format!("Failed to create TUN device: {e}"))?;

    tracing::info!("[VPN] TUN device created: {} ({})", config.name, gateway_ip);

    // Auto-configure IP forwarding and NAT
    setup_ip_forwarding(&config.name, gateway_ip, netmask);

    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let _ = TUN_WRITE_TX.set(write_tx);

    // On Windows, wintun Session is Arc and supports concurrent read/write.
    // Split into two separate tasks to avoid &mut self conflicts in select!.

    #[cfg(target_os = "windows")]
    {
        // Writer task: receive packets from peers and write to TUN
        // TUN device now uses dedicated threads internally, so write() is cheap
        let write_channel = tun.write_tx.clone();
        let write_task = tokio::spawn(async move {
            while let Some(packet) = write_rx.recv().await {
                if let Err(e) = write_channel.send(packet) {
                    tracing::error!("[VPN] TUN write error: {}", e);
                    break;
                }
            }
            tracing::info!("[VPN] TUN writer task ended");
        });

        // Reader task: read from TUN and route to correct peer (runs on current task)
        let mut read_buf = vec![0u8; 65536];
        loop {
            match tun.read(&mut read_buf).await {
                Ok(n) if n >= 20 => {
                    let packet = &read_buf[..n];
                    // Skip non-IPv4
                    if (packet[0] >> 4) != 4 {
                        continue;
                    }
                    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                    let vs = vpn_state.lock().await;
                    if let Some(route_tx) = vs.routes.get(&dst_ip) {
                        tracing::debug!("[VPN] TUN->client: {} -> {} ({} bytes)", src_ip, dst_ip, n);
                        let mut frame = Vec::with_capacity(1 + n);
                        frame.push(VPN_TUNNEL_MAGIC);
                        frame.extend_from_slice(packet);
                        let _ = route_tx.send(frame);
                    } else {
                        tracing::debug!("[VPN] TUN read: {} -> {} ({} bytes) - no route", src_ip, dst_ip, n);
                    }
                }
                Ok(n) => {
                    tracing::debug!("[VPN] TUN read: short packet ({} bytes)", n);
                }
                Err(e) => {
                    tracing::error!("[VPN] TUN read error: {}", e);
                    break;
                }
            }
        }

        write_task.abort();
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On Linux, the tun crate's AsyncDevice supports concurrent read/write natively
        let mut read_buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                result = tun.read(&mut read_buf) => {
                    match result {
                        Ok(n) if n >= 20 => {
                            let packet = &read_buf[..n];
                            let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                            let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                            let vs = vpn_state.lock().await;
                            if let Some(route_tx) = vs.routes.get(&dst_ip) {
                                tracing::debug!("[VPN] TUN->client: {} -> {} ({} bytes)", src_ip, dst_ip, n);
                                let mut frame = Vec::with_capacity(1 + n);
                                frame.push(VPN_TUNNEL_MAGIC);
                                frame.extend_from_slice(packet);
                                let _ = route_tx.send(frame);
                            } else {
                                tracing::debug!("[VPN] TUN read: {} -> {} ({} bytes) - no route", src_ip, dst_ip, n);
                            }
                        }
                        Ok(n) => {
                            tracing::debug!("[VPN] TUN read: short packet ({} bytes)", n);
                        }
                        Err(e) => {
                            tracing::error!("[VPN] TUN read error: {}", e);
                            break;
                        }
                    }
                }
                data = write_rx.recv() => {
                    match data {
                        Some(packet) => {
                            if let Err(e) = tun.write(&packet).await {
                                tracing::error!("[VPN] TUN write error: {}", e);
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    }

    Ok(())
}

/// Called from the system tray toggle to enable VPN forwarding.
pub fn enable_forwarding() {
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING", "-s", "10.66.0.0/24", "-j", "MASQUERADE"])
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("reg")
            .args(["add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"])
            .status();
    }
}

/// Called from the system tray toggle to disable VPN forwarding.
pub fn disable_forwarding() {
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "0");
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-s", "10.66.0.0/24", "-j", "MASQUERADE"])
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("reg")
            .args(["add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "0", "/f"])
            .status();
    }
}

/// Automatically configure IP forwarding and NAT on the bridge host.
fn setup_ip_forwarding(_tun_name: &str, gateway_ip: Ipv4Addr, netmask: Ipv4Addr) {
    let subnet = format!("{}/{}",
        {
            let o = gateway_ip.octets();
            let m = netmask.octets();
            Ipv4Addr::new(o[0] & m[0], o[1] & m[1], o[2] & m[2], o[3] & m[3])
        },
        netmask.octets().iter().map(|b| b.count_ones()).sum::<u32>()
    );

    #[cfg(target_os = "linux")]
    {
        // Enable IP forwarding
        match std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
            Ok(_) => tracing::info!("[VPN] IP forwarding enabled"),
            Err(e) => {
                tracing::warn!("[VPN] Could not enable IP forwarding: {e}");
                tracing::warn!("[VPN] Run: sudo sysctl net.ipv4.ip_forward=1");
            }
        }

        // Add iptables MASQUERADE rule (idempotent with -C check)
        let check = std::process::Command::new("iptables")
            .args(["-t", "nat", "-C", "POSTROUTING", "-s", &subnet, "-j", "MASQUERADE"])
            .output();

        match check {
            Ok(output) if output.status.success() => {
                tracing::info!("[VPN] NAT rule already exists for {subnet}");
            }
            _ => {
                let result = std::process::Command::new("iptables")
                    .args(["-t", "nat", "-A", "POSTROUTING", "-s", &subnet, "-j", "MASQUERADE"])
                    .status();
                match result {
                    Ok(s) if s.success() => tracing::info!("[VPN] NAT masquerade rule added for {subnet}"),
                    Ok(s) => tracing::warn!("[VPN] iptables exited with {s}. Run manually: iptables -t nat -A POSTROUTING -s {subnet} -j MASQUERADE"),
                    Err(e) => tracing::warn!("[VPN] Failed to run iptables: {e}. Run manually: iptables -t nat -A POSTROUTING -s {subnet} -j MASQUERADE"),
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows: enable IP routing via registry + ICS
        let result = std::process::Command::new("reg")
            .args(["add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"])
            .status();
        match result {
            Ok(s) if s.success() => tracing::info!("[VPN] IP routing enabled in registry"),
            _ => tracing::warn!("[VPN] Could not enable IP routing. Enable manually in Windows network settings."),
        }
        let _ = subnet; // suppress unused warning
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = subnet;
        tracing::warn!("[VPN] Auto IP forwarding not implemented for this platform");
    }
}
