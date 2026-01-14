use serde::{Deserialize, Serialize};

/// TLS 配置（服务端）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

/// TLS 配置（客户端）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientConfig {
    pub enabled: bool,
    pub ca_cert_path: String,
    pub insecure_skip_verify: bool,
}
