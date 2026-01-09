use serde::{Deserialize, Serialize};

/// 消息类型枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Handshake,
    Heartbeat,
    Data,
    Control,
    Auth,
    ConnectRequest,
    ConnectResponse,
    Close,
}

/// 连接状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connecting,
    Connected,
    Disconnected,
    Error,
}

/// 隧道类型枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelType {
    TCP,
    UDP,
    HTTP,
    HTTPS,
    WebSocket,
}