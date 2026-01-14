use async_trait::async_trait;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rystra_model::{Error, Result};
use rystra_plugin::{TransportListener, TransportPlugin, TransportStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub struct HttpTransportPlugin {
    proxy_url: Option<String>,
}

impl HttpTransportPlugin {
    pub fn new() -> Self {
        Self { proxy_url: None }
    }

    pub fn with_proxy(proxy_url: String) -> Self {
        Self {
            proxy_url: Some(proxy_url),
        }
    }
}

impl Default for HttpTransportPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportPlugin for HttpTransportPlugin {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn listen(&self, addr: &str) -> Result<Box<dyn TransportListener>> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::other(format!("failed to bind {}: {}", addr, e)))?;

        Ok(Box::new(HttpTransportListener {
            inner: Arc::new(Mutex::new(listener)),
        }))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn TransportStream>> {
        if let Some(proxy_url) = &self.proxy_url {
            connect_via_http_proxy(proxy_url, addr).await
        } else {
            connect_direct(addr).await
        }
    }
}

async fn connect_direct(addr: &str) -> Result<Box<dyn TransportStream>> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| Error::other(format!("failed to connect {}: {}", addr, e)))?;

    Ok(Box::new(HttpTransportStream { inner: stream }))
}

async fn connect_via_http_proxy(proxy_url: &str, target_addr: &str) -> Result<Box<dyn TransportStream>> {
    let proxy_uri: Uri = proxy_url
        .parse()
        .map_err(|e| Error::config(format!("invalid proxy URL: {}", e)))?;

    let proxy_host = proxy_uri
        .host()
        .ok_or_else(|| Error::config("proxy URL missing host"))?;
    let proxy_port = proxy_uri.port_u16().unwrap_or(80);
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

    let mut stream = TcpStream::connect(&proxy_addr)
        .await
        .map_err(|e| Error::other(format!("failed to connect to proxy {}: {}", proxy_addr, e)))?;

    let connect_req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        target_addr, target_addr
    );

    tokio::io::AsyncWriteExt::write_all(&mut stream, connect_req.as_bytes())
        .await
        .map_err(|e| Error::other(format!("failed to send CONNECT: {}", e)))?;

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
        .await
        .map_err(|e| Error::other(format!("failed to read CONNECT response: {}", e)))?;

    let response = String::from_utf8_lossy(&buf[..n]);
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        return Err(Error::other(format!(
            "HTTP CONNECT failed: {}",
            response.lines().next().unwrap_or("")
        )));
    }

    Ok(Box::new(HttpTransportStream { inner: stream }))
}

pub struct HttpTransportListener {
    inner: Arc<Mutex<TcpListener>>,
}

#[async_trait]
impl TransportListener for HttpTransportListener {
    async fn accept(&self) -> Result<Box<dyn TransportStream>> {
        let listener = self.inner.lock().await;
        let (stream, _addr) = listener
            .accept()
            .await
            .map_err(|e| Error::other(format!("failed to accept: {}", e)))?;

        drop(listener);

        handle_http_connect(stream).await
    }
}

async fn handle_http_connect(stream: TcpStream) -> Result<Box<dyn TransportStream>> {
    let io = TokioIo::new(stream);
    let stream_ref = Arc::new(Mutex::new(None));
    let stream_ref_clone = stream_ref.clone();

    let service = service_fn(move |req: Request<Incoming>| {
        let stream_ref = stream_ref_clone.clone();
        async move {
            if req.method() == Method::CONNECT {
                tokio::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            *stream_ref.lock().await = Some(upgraded);
                        }
                        Err(e) => {
                            eprintln!("upgrade error: {}", e);
                        }
                    }
                });

                Ok::<_, hyper::Error>(Response::new(String::from("OK")))
            } else {
                let mut response = Response::new(String::from("Method not allowed"));
                *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                Ok(response)
            }
        }
    });

    if let Err(e) = http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        return Err(Error::other(format!("HTTP serve error: {}", e)));
    }

    let upgraded_stream = stream_ref
        .lock()
        .await
        .take()
        .ok_or_else(|| Error::other("failed to upgrade HTTP connection"))?;

    Ok(Box::new(HttpUpgradedStream {
        inner: TokioIo::new(upgraded_stream),
    }))
}

pub struct HttpTransportStream {
    inner: TcpStream,
}

impl TransportStream for HttpTransportStream {}

impl AsyncRead for HttpTransportStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpTransportStream {
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

pub struct HttpUpgradedStream {
    inner: TokioIo<hyper::upgrade::Upgraded>,
}

impl TransportStream for HttpUpgradedStream {}

impl AsyncRead for HttpUpgradedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpUpgradedStream {
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