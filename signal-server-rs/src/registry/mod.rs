use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize)]
pub struct GatewayMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backends: Option<Vec<BackendInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// TideCloak issuer this gateway trusts (`<auth-server-url>/realms/<realm>`).
    /// Descriptive only — unlike `realm` it is always advertised, so it can be
    /// used to tell tenants apart without affecting HTTP relay routing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The gateway's current editable settings, as it reported them. Relayed
    /// verbatim so a console can list a self-registered gateway accurately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

pub type WsSender = mpsc::UnboundedSender<axum::extract::ws::Message>;

pub struct Gateway {
    pub id: String,
    pub addresses: Vec<String>,
    pub sender: WsSender,
    pub registered_at: u64,
    pub paired_clients: HashSet<String>,
    pub metadata: GatewayMetadata,
    pub public_ip: Option<String>,
}

pub struct Client {
    pub id: String,
    pub sender: WsSender,
    pub registered_at: u64,
    pub reflexive_address: Option<String>,
    pub paired_gateway_id: Option<String>,
    pub token: String,
    pub connection_type: String,
}

pub struct Registry {
    gateways: DashMap<String, Gateway>,
    clients: DashMap<String, Client>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            gateways: DashMap::new(),
            clients: DashMap::new(),
        }
    }

    pub fn register_gateway(
        &self,
        id: String,
        addresses: Vec<String>,
        sender: WsSender,
        metadata: GatewayMetadata,
        public_ip: Option<String>,
    ) {
        // If gateway already exists, update it
        if let Some(mut existing) = self.gateways.get_mut(&id) {
            existing.addresses = addresses;
            existing.sender = sender;
            existing.metadata = metadata;
            existing.public_ip = public_ip;
            tracing::info!("[Signal] Gateway re-registered: {id}");
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.gateways.insert(id.clone(), Gateway {
                id: id.clone(),
                addresses,
                sender,
                registered_at: now,
                paired_clients: HashSet::new(),
                metadata,
                public_ip,
            });
            tracing::info!("[Signal] Gateway registered: {id}");
        }
    }

    pub fn register_client(&self, id: String, sender: WsSender, token: String) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.clients.insert(id.clone(), Client {
            id,
            sender,
            registered_at: now,
            reflexive_address: None,
            paired_gateway_id: None,
            token,
            connection_type: "relay".to_string(),
        });
    }

    pub fn update_client_reflexive(&self, id: &str, addr: &str) {
        if let Some(mut client) = self.clients.get_mut(id) {
            client.reflexive_address = Some(addr.to_string());
        }
    }

    pub fn get_gateway(&self, id: &str) -> Option<dashmap::mapref::one::Ref<String, Gateway>> {
        self.gateways.get(id)
    }

    pub fn get_client(&self, id: &str) -> Option<dashmap::mapref::one::Ref<String, Client>> {
        self.clients.get(id)
    }

    pub fn get_client_mut(&self, id: &str) -> Option<dashmap::mapref::one::RefMut<String, Client>> {
        self.clients.get_mut(id)
    }

    pub fn get_gateway_mut(&self, id: &str) -> Option<dashmap::mapref::one::RefMut<String, Gateway>> {
        self.gateways.get_mut(id)
    }

    pub fn get_available_gateway(&self) -> Option<String> {
        let mut best_id = None;
        let mut min_clients = usize::MAX;
        for entry in self.gateways.iter() {
            if entry.paired_clients.len() < min_clients {
                min_clients = entry.paired_clients.len();
                best_id = Some(entry.id.clone());
            }
        }
        best_id
    }

    pub fn get_gateway_by_backend(&self, backend_name: &str) -> Option<String> {
        for entry in self.gateways.iter() {
            if let Some(ref backends) = entry.metadata.backends {
                for b in backends {
                    if b.name.eq_ignore_ascii_case(backend_name) {
                        return Some(entry.id.clone());
                    }
                }
            }
        }
        None
    }

    pub fn get_gateway_by_realm(&self, realm: &str) -> Option<String> {
        for entry in self.gateways.iter() {
            if let Some(ref r) = entry.metadata.realm {
                if r.eq_ignore_ascii_case(realm) {
                    return Some(entry.id.clone());
                }
            }
        }
        None
    }

    pub fn get_all_gateways(&self) -> Vec<String> {
        self.gateways.iter().map(|e| e.id.clone()).collect()
    }

    pub fn remove_gateway(&self, id: &str) {
        self.gateways.remove(id);
        tracing::info!("[Signal] Gateway unregistered: {id}");
    }

    pub fn remove_client(&self, id: &str) {
        // Remove from paired gateway
        if let Some(client) = self.clients.get(id) {
            if let Some(ref gw_id) = client.paired_gateway_id {
                if let Some(mut gw) = self.gateways.get_mut(gw_id) {
                    gw.paired_clients.remove(id);
                }
            }
        }
        self.clients.remove(id);
    }

    pub fn send_to_gateway(&self, id: &str, msg: axum::extract::ws::Message) -> bool {
        if let Some(gw) = self.gateways.get(id) {
            gw.sender.send(msg).is_ok()
        } else {
            false
        }
    }

    pub fn send_to_client(&self, id: &str, msg: axum::extract::ws::Message) -> bool {
        if let Some(client) = self.clients.get(id) {
            client.sender.send(msg).is_ok()
        } else {
            false
        }
    }

    pub fn gateway_count(&self) -> usize {
        self.gateways.len()
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }
}

// ---------------------------------------------------------------------------
// Tests — ported from tests/signal-server/registry.test.ts (Node signal
// server) to preserve coverage after the Node signal server was removed.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> WsSender {
        // Detached channel; we only need the sender end for registration.
        mpsc::unbounded_channel().0
    }

    fn meta() -> GatewayMetadata {
        GatewayMetadata {
            display_name: None,
            description: None,
            backends: None,
            realm: None,
            issuer: None,
            client_id: None,
            config: None,
            public_url: None,
        }
    }

    #[test]
    fn register_gateway_and_lookup() {
        let r = Registry::new();
        r.register_gateway("gw-1".into(), vec!["1.2.3.4:443".into()], sender(), meta(), None);
        assert!(r.get_gateway("gw-1").is_some());
        assert_eq!(r.get_gateway("gw-1").unwrap().id, "gw-1");
    }

    #[test]
    fn register_gateway_stores_metadata() {
        let r = Registry::new();
        let m = GatewayMetadata {
            display_name: Some("My Gateway".into()),
            description: Some("Test gateway".into()),
            backends: Some(vec![BackendInfo { name: "App".into(), protocol: Some("http".into()), auth: None }]),
            realm: Some("keylessh".into()),
            issuer: Some("https://tc.example.com/realms/keylessh".into()),
            client_id: Some("punchd".into()),
            config: None,
            public_url: None,
        };
        r.register_gateway("gw-1".into(), vec!["1.2.3.4:443".into()], sender(), m, None);
        let gw = r.get_gateway("gw-1").unwrap();
        assert_eq!(gw.metadata.display_name.as_deref(), Some("My Gateway"));
        assert_eq!(gw.metadata.description.as_deref(), Some("Test gateway"));
        assert_eq!(gw.metadata.backends.as_ref().unwrap().len(), 1);
        assert_eq!(gw.metadata.realm.as_deref(), Some("keylessh"));
        assert_eq!(gw.metadata.issuer.as_deref(), Some("https://tc.example.com/realms/keylessh"));
        assert_eq!(gw.metadata.client_id.as_deref(), Some("punchd"));
    }

    #[test]
    fn re_register_updates_addresses_and_preserves_paired_clients() {
        let r = Registry::new();
        r.register_gateway("gw-1".into(), vec!["1.2.3.4:443".into()], sender(), meta(), None);
        r.register_client("client-1".into(), sender(), String::new());
        r.get_gateway_mut("gw-1").unwrap().paired_clients.insert("client-1".into());

        // Re-register with new address/sender
        r.register_gateway("gw-1".into(), vec!["5.6.7.8:443".into()], sender(), meta(), None);
        let gw = r.get_gateway("gw-1").unwrap();
        assert_eq!(gw.addresses, vec!["5.6.7.8:443".to_string()]);
        assert!(gw.paired_clients.contains("client-1"));
    }

    #[test]
    fn register_client_defaults_to_relay_and_stores_token() {
        let r = Registry::new();
        r.register_client("client-1".into(), sender(), "my-jwt-token".into());
        let c = r.get_client("client-1").unwrap();
        assert_eq!(c.connection_type, "relay");
        assert_eq!(c.token, "my-jwt-token");
    }

    #[test]
    fn remove_gateway_and_client() {
        let r = Registry::new();
        r.register_gateway("gw-1".into(), vec![], sender(), meta(), None);
        r.remove_gateway("gw-1");
        assert!(r.get_gateway("gw-1").is_none());

        r.register_client("client-1".into(), sender(), String::new());
        r.remove_client("client-1");
        assert!(r.get_client("client-1").is_none());
    }

    #[test]
    fn removing_client_unpairs_it_from_gateway() {
        let r = Registry::new();
        r.register_gateway("gw-1".into(), vec![], sender(), meta(), None);
        r.register_client("client-1".into(), sender(), String::new());
        r.get_gateway_mut("gw-1").unwrap().paired_clients.insert("client-1".into());
        r.get_client_mut("client-1").unwrap().paired_gateway_id = Some("gw-1".into());

        r.remove_client("client-1");
        assert!(!r.get_gateway("gw-1").unwrap().paired_clients.contains("client-1"));
    }

    #[test]
    fn get_available_gateway_prefers_fewest_clients() {
        let r = Registry::new();
        assert!(r.get_available_gateway().is_none());

        r.register_gateway("gw-1".into(), vec![], sender(), meta(), None);
        assert_eq!(r.get_available_gateway().as_deref(), Some("gw-1"));

        r.register_gateway("gw-2".into(), vec![], sender(), meta(), None);
        // 3 clients on gw-1, 1 on gw-2 -> gw-2 wins
        for c in ["c1", "c2", "c3"] {
            r.get_gateway_mut("gw-1").unwrap().paired_clients.insert(c.into());
        }
        r.get_gateway_mut("gw-2").unwrap().paired_clients.insert("c4".into());
        assert_eq!(r.get_available_gateway().as_deref(), Some("gw-2"));
    }

    #[test]
    fn get_gateway_by_realm() {
        let r = Registry::new();
        let m = GatewayMetadata { realm: Some("keylessh".into()), ..meta() };
        r.register_gateway("gw-1".into(), vec![], sender(), m, None);
        assert_eq!(r.get_gateway_by_realm("keylessh").as_deref(), Some("gw-1"));
        assert!(r.get_gateway_by_realm("other").is_none());
    }

    #[test]
    fn update_client_reflexive_and_counts() {
        let r = Registry::new();
        assert_eq!(r.gateway_count(), 0);
        assert_eq!(r.client_count(), 0);

        r.register_client("client-1".into(), sender(), String::new());
        r.update_client_reflexive("client-1", "203.0.113.5:12345");
        assert_eq!(r.get_client("client-1").unwrap().reflexive_address.as_deref(), Some("203.0.113.5:12345"));
        // no-op for unknown
        r.update_client_reflexive("unknown", "1.2.3.4");

        r.register_gateway("gw-1".into(), vec![], sender(), meta(), None);
        r.register_gateway("gw-2".into(), vec![], sender(), meta(), None);
        assert_eq!(r.gateway_count(), 2);
        assert_eq!(r.client_count(), 1);
    }

    #[test]
    fn get_all_gateways() {
        let r = Registry::new();
        assert!(r.get_all_gateways().is_empty());
        r.register_gateway("gw-1".into(), vec![], sender(), meta(), None);
        r.register_gateway("gw-2".into(), vec![], sender(), meta(), None);
        let mut all = r.get_all_gateways();
        all.sort();
        assert_eq!(all, vec!["gw-1".to_string(), "gw-2".to_string()]);
    }

    #[test]
    fn send_to_gateway_and_client_reports_presence() {
        let r = Registry::new();
        let (gw_tx, mut gw_rx) = mpsc::unbounded_channel();
        r.register_gateway("gw-1".into(), vec![], gw_tx, meta(), None);
        assert!(r.send_to_gateway("gw-1", axum::extract::ws::Message::Text("hi".to_string().into())));
        assert!(gw_rx.try_recv().is_ok());
        // unknown target -> false
        assert!(!r.send_to_client("nobody", axum::extract::ws::Message::Text("x".to_string().into())));
    }
}
