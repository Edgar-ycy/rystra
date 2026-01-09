use serde::{Deserialize, Serialize};
use crate::protocol::types::TunnelType;

/// 隧道配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub name: String,
    pub tunnel_type: TunnelType,
    pub local_address: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub enabled: bool,
    pub encryption: bool,
}

/// 激活隧道实例
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveTunnel {
    pub config: TunnelConfig,
    pub session_id: String,
    pub connected_at: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub status: String,
}