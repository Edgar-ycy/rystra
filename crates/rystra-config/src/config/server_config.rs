use crate::ConfigValidation;
use crate::config::web_server_config::WebServerConfig;
use rystra_model::Error;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_web_server")]
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
fn default_log_level() -> String {
    "info".to_string()
}
fn default_web_server() -> WebServerConfig {
    WebServerConfig {
        addr: "127.0.0.1".to_string(),
        port: 8800,
        user: "admin".to_string(),
        password: "admin".to_string(),
    }
}

impl ConfigValidation for ServerConfig {
    fn validate(&self) -> rystra_model::Result<()> {
        if self.bind_port == 0 {
            return Err(Error::config("bind_port cannot be 0"));
        }
        Ok(())
    }
}

impl ServerConfig {
    pub fn load_from_file(path: impl AsRef<Path>) -> rystra_model::Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .map_err(|e| Error::config(format!("read file failed ({}): {}", path.display(), e)))?;
        let cfg: ServerConfig = toml::from_str(&text)
            .map_err(|e| Error::config(format!("parse toml failed ({}): {}", path.display(), e)))?;

        if cfg.validate().is_err() {
            return Err(Error::config(format!(
                "parse toml failed ({}): validate failed",
                path.display()
            )));
        }
        Ok(cfg)
    }
}