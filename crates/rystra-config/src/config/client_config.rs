use crate::ConfigValidation;
use crate::config::Proxy;
use crate::config::WebServerConfig;
use rystra_model::Error;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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

fn default_web_server_1() -> WebServerConfig {
    WebServerConfig {
        addr: "127.0.0.1".to_string(),
        port: 8600,
        user: "admin".to_string(),
        password: "admin".to_string(),
    }
}

impl ConfigValidation for ClientConfig {
    fn validate(&self) -> rystra_model::Result<()> {
        if self.server_bind_port == 0 {
            return Err(Error::config(
                "parse toml failed (监听端口设置错误)".to_string(),
            ));
        }
        Ok(())
    }
}

impl ClientConfig {
    pub fn load_from_file(path: impl AsRef<Path>) -> rystra_model::Result<Self> {
        let path = path.as_ref();

        // 1) 读取文件：这里的 io::Error 会自动转换成 rystra_model::Error（你第二步已经实现了 From）
        let text = fs::read_to_string(path)
            .map_err(|e| Error::config(format!("read file failed ({}): {}", path.display(), e)))?;

        // 2) 解析 toml：toml::de::Error 不是我们的 Error，需要手动映射到 Error::Config
        let cfg: ClientConfig = toml::from_str(&text)
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
