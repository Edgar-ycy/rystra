use std::fmt;

/// 应用程序的核心错误类型
#[derive(Debug, Clone)]
pub enum CoreError {
    NetworkError(String),
    AuthenticationError(String),
    ConfigurationError(String),
    ProtocolError(String),
    IoError(String),
    SerializationError(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            CoreError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            CoreError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            CoreError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            CoreError::IoError(msg) => write!(f, "IO error: {}", msg),
            CoreError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for CoreError {}

/// Result 类型 别名
pub type Result<T> = std::result::Result<T, CoreError>;