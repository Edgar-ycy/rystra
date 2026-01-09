use serde::{Deserialize, Serialize};
pub use crate::protocol::types::{MessageType, TunnelType};

/// Protocol message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub msg_type: MessageType,
    pub session_id: Option<String>,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

/// 验证 message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMessage {
    pub token: String,
    pub client_version: String,
    pub capabilities: Vec<String>,
}

/// 隧道建立请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub tunnel_type: TunnelType,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub name: String,
}

/// 响应隧道建立请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelResponse {
    pub success: bool,
    pub message: String,
    pub assigned_port: Option<u16>,
}