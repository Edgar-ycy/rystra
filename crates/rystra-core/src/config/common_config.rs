use serde::{Deserialize, Serialize};

/// 服务端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_web_server_0")]
    pub web_server: WebServerConfig,
    
}
fn default_bind_addr() -> String {
    "0.0.0.0".to_string()
}
fn default_bind_port() -> u16 {
    8000
}
fn default_max_connections() -> usize {
    10
}

/// 客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_bind_port: u16,
    #[serde(default = "default_proxies")]
    pub proxies: Vec<Proxy>,
    #[serde(default = "default_web_server_1")]
    pub web_server: WebServerConfig,

}
fn default_proxies() -> Vec<Proxy> {
    vec![]
}
fn default_web_server_0() -> WebServerConfig {
    WebServerConfig {
        addr: "127.0.0.1".to_string(),
        port: 8800,
        user: "admin".to_string(),
        password: "admin".to_string(),
    }
}
fn default_web_server_1() -> WebServerConfig {
    WebServerConfig {
        addr: "127.0.0.1".to_string(),
        port: 8600,
        user: "admin".to_string(),
        password: "admin".to_string(),
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    pub name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebServerConfig {
    pub addr: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}