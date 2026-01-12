use crate::ConfigValidation;
use crate::config::web_server_config::WebServerConfig;
use rystra_model::Error;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// 服务端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
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
            return Err(Error::config(
                "parse toml failed (监听端口设置错误)".to_string(),
            ));
        }
        Ok(())
    }
}

impl ServerConfig {
    /// 从 toml 文件加载配置
    pub fn load_from_file(path: impl AsRef<Path>) -> rystra_model::Result<Self> {
        let path = path.as_ref();

        // 1) 读取文件：这里的 io::Error 会自动转换成 rystra_model::Error（你第二步已经实现了 From）
        let text = fs::read_to_string(path)
            .map_err(|e| Error::config(format!("read file failed ({}): {}", path.display(), e)))?;

        // 2) 解析 toml：toml::de::Error 不是我们的 Error，需要手动映射到 Error::Config
        let cfg: ServerConfig = toml::from_str(&text)
            .map_err(|e| Error::config(format!("parse toml failed ({}): {}", path.display(), e)))?;

        if cfg.validate().is_err() {
            return Err(Error::config(format!(
                "parse toml failed ({}): {}",
                path.display(),
                "validate failed"
            )));
        }

        Ok(cfg)
    }
}
