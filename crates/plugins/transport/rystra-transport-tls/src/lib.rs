use async_trait::async_trait;
use rystra_model::{Error, Result};
use rystra_plugin::{TransportListener, TransportPlugin, TransportStream};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct TlsTransportPlugin {
    server_config: Option<Arc<ServerConfig>>,
    client_config: Option<Arc<ClientConfig>>,
}

impl TlsTransportPlugin {
    pub fn new_server(cert_path: &str, key_path: &str) -> Result<Self> {
        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::config(format!("TLS config error: {}", e)))?;

        Ok(Self {
            server_config: Some(Arc::new(config)),
            client_config: None,
        })
    }

    pub fn new_client(ca_path: &str) -> Result<Self> {
        let mut root_store = RootCertStore::empty();
        let ca_certs = load_certs(ca_path)?;
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| Error::config(format!("add CA cert error: {}", e)))?;
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }

    pub fn new_client_insecure() -> Result<Self> {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {}))
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }
}

#[async_trait]
impl TransportPlugin for TlsTransportPlugin {
    fn name(&self) -> &'static str {
        "tls"
    }

    async fn listen(&self, addr: &str) -> Result<Box<dyn TransportListener>> {
        let config = self
            .server_config
            .as_ref()
            .ok_or_else(|| Error::config("TLS server config not set"))?;
        let listener = TcpListener::bind(addr).await?;
        let acceptor = TlsAcceptor::from(config.clone());
        Ok(Box::new(TlsTransportListener { listener, acceptor }))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn TransportStream>> {
        let config = self
            .client_config
            .as_ref()
            .ok_or_else(|| Error::config("TLS client config not set"))?;
        let connector = TlsConnector::from(config.clone());
        let stream = TcpStream::connect(addr).await?;

        let domain = addr.split(':').next().unwrap_or("localhost");
        let domain = domain
            .to_string()
            .try_into()
            .map_err(|_| Error::config("invalid domain"))?;

        let tls_stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| Error::other(format!("TLS connect error: {}", e)))?;

        Ok(Box::new(TlsClientStream { inner: tls_stream }))
    }
}

pub struct TlsTransportListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

#[async_trait]
impl TransportListener for TlsTransportListener {
    async fn accept(&self) -> Result<Box<dyn TransportStream>> {
        let (stream, _addr) = self.listener.accept().await?;
        let tls_stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(|e| Error::other(format!("TLS accept error: {}", e)))?;
        Ok(Box::new(TlsServerStream { inner: tls_stream }))
    }
}

pub struct TlsServerStream {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
}

impl TransportStream for TlsServerStream {}

impl AsyncRead for TlsServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsServerStream {
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

pub struct TlsClientStream {
    inner: tokio_rustls::client::TlsStream<TcpStream>,
}

impl TransportStream for TlsClientStream {}

impl AsyncRead for TlsClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsClientStream {
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

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(Path::new(path))
        .map_err(|e| Error::config(format!("open cert file {} error: {}", path, e)))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::config(format!("parse cert error: {}", e)))
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(Path::new(path))
        .map_err(|e| Error::config(format!("open key file {} error: {}", path, e)))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::config(format!("parse key error: {}", e)))?
        .ok_or_else(|| Error::config("no private key found"))
}

mod danger {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}
