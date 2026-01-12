use async_trait::async_trait;
use rystra_model::{Error, Result};
use rystra_plugin::{TransportListener, TransportPlugin, TransportStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub struct TcpTransportPlugin;

impl TcpTransportPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TcpTransportPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportPlugin for TcpTransportPlugin {
    fn name(&self) -> &'static str {
        "tcp"
    }

    async fn listen(&self, addr: &str) -> Result<Box<dyn TransportListener>> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::other(format!("failed to bind {}: {}", addr, e)))?;
        Ok(Box::new(TcpTransportListener {
            inner: Arc::new(Mutex::new(listener)),
        }))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn TransportStream>> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::other(format!("failed to connect {}: {}", addr, e)))?;
        Ok(Box::new(TcpTransportStream { inner: stream }))
    }
}

pub struct TcpTransportListener {
    inner: Arc<Mutex<TcpListener>>,
}

#[async_trait]
impl TransportListener for TcpTransportListener {
    async fn accept(&self) -> Result<Box<dyn TransportStream>> {
        let listener = self.inner.lock().await;
        let (stream, _addr) = listener
            .accept()
            .await
            .map_err(|e| Error::other(format!("failed to accept: {}", e)))?;
        Ok(Box::new(TcpTransportStream { inner: stream }))
    }
}

pub struct TcpTransportStream {
    inner: TcpStream,
}

impl TransportStream for TcpTransportStream {}

impl AsyncRead for TcpTransportStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpTransportStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}