use async_trait::async_trait;
use rystra_model::Result;
use tokio::io::{AsyncRead, AsyncWrite};

/// 传输层插件 trait
#[async_trait]
pub trait TransportPlugin: Send + Sync {
    fn name(&self) -> &'static str;

    async fn listen(&self, addr: &str) -> Result<Box<dyn TransportListener>>;

    async fn connect(&self, addr: &str) -> Result<Box<dyn TransportStream>>;
}

/// 传输层监听器
#[async_trait]
pub trait TransportListener: Send + Sync {
    async fn accept(&self) -> Result<Box<dyn TransportStream>>;
}

/// 传输层连接流
pub trait TransportStream: AsyncRead + AsyncWrite + Send + Unpin {}

/// 认证插件 trait
#[async_trait]
pub trait AuthPlugin: Send + Sync {
    fn name(&self) -> &'static str;

    async fn verify(&self, token: &str) -> Result<bool>;
}

/// 代理插件 trait
pub trait ProxyPlugin: Send + Sync {
    fn name(&self) -> &'static str;

    fn proxy_type(&self) -> &'static str;
}