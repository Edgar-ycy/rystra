use serde::{Deserialize, Serialize};

/// 用户模型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub created_at: u64,
    pub last_login: Option<u64>,
    pub is_active: bool,
}