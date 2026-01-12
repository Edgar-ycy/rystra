use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ProxyEntry {
    pub name: String,
    pub remote_port: u16,
    pub local_addr: String,
    pub local_port: u16,
    pub client_id: String,
}

pub struct ProxyManager {
    proxies: RwLock<HashMap<String, ProxyEntry>>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self {
            proxies: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, entry: ProxyEntry) -> bool {
        let mut proxies = self.proxies.write().unwrap();
        if proxies.contains_key(&entry.name) {
            return false;
        }
        proxies.insert(entry.name.clone(), entry);
        true
    }

    pub fn unregister(&self, name: &str) -> Option<ProxyEntry> {
        let mut proxies = self.proxies.write().unwrap();
        proxies.remove(name)
    }

    pub fn get(&self, name: &str) -> Option<ProxyEntry> {
        let proxies = self.proxies.read().unwrap();
        proxies.get(name).cloned()
    }

    pub fn get_by_port(&self, port: u16) -> Option<ProxyEntry> {
        let proxies = self.proxies.read().unwrap();
        proxies.values().find(|p| p.remote_port == port).cloned()
    }

    pub fn list(&self) -> Vec<ProxyEntry> {
        let proxies = self.proxies.read().unwrap();
        proxies.values().cloned().collect()
    }

    pub fn unregister_by_client(&self, client_id: &str) {
        let mut proxies = self.proxies.write().unwrap();
        proxies.retain(|_, v| v.client_id != client_id);
    }
}

impl Default for ProxyManager {
    fn default() -> Self {
        Self::new()
    }
}
