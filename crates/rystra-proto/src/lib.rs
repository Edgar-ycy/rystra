use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub client_id: String,
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterProxy {
    pub name: String,
    pub remote_port: u16,
    pub local_addr: String,
    pub local_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterProxyResponse {
    pub name: String,
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStream {
    pub proxy_name: String,
    pub stream_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamReady {
    pub stream_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Hello(Hello),
    AuthRequest(AuthRequest),
    AuthResponse(AuthResponse),
    Heartbeat,
    RegisterProxy(RegisterProxy),
    RegisterProxyResponse(RegisterProxyResponse),
    OpenStream(OpenStream),
    StreamReady(StreamReady),
}