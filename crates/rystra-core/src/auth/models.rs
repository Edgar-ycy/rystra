use serde::{Deserialize, Serialize};
use crate::auth::token::AuthMethod;

/// 用户身份识别
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub user_id: String,
    pub username: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub auth_method: AuthMethod,
}

/// RBAC角色
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<String>,
    pub description: String,
}

/// 存取控制列表
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub user_id: String,
    pub resource: String,
    pub permissions: Vec<String>,
    pub allowed_ips: Vec<String>,
}