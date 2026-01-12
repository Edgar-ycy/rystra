use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebServerConfig {
    pub addr: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}
