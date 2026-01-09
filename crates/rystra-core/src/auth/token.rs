use serde::{Deserialize, Serialize};

/// 支持的认证方法
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    JWTToken,
    Oidc,
    APIKey,
    Certificate,
}

/// 认证token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub value: String,
    pub expiration: u64,
    pub issued_at: u64,
    pub user_id: String,
    pub method: AuthMethod,
}

/// API 密钥 struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub key: String,
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}