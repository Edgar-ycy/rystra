use serde::{Deserialize, Serialize};

/// 连接状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    Initial,
    Connecting,
    Connected,
    Authenticating,
    Authenticated,
    Ready,
    Closing,
    Closed,
}

/// 连接信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub remote_addr: String,
    pub state: ConnectionState,
    pub connected_at: u64,
    pub last_activity: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}