use async_trait::async_trait;
use rystra_model::Result;
use rystra_plugin::AuthPlugin;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;

pub struct TokenAuthPlugin {
    valid_tokens: Arc<RwLock<HashSet<String>>>,
}

impl TokenAuthPlugin {
    pub fn new() -> Self {
        Self {
            valid_tokens: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn with_tokens(tokens: Vec<String>) -> Self {
        let set: HashSet<String> = tokens.into_iter().collect();
        Self {
            valid_tokens: Arc::new(RwLock::new(set)),
        }
    }

    pub fn add_token(&self, token: String) {
        let mut tokens = self.valid_tokens.write().unwrap();
        tokens.insert(token);
    }

    pub fn remove_token(&self, token: &str) {
        let mut tokens = self.valid_tokens.write().unwrap();
        tokens.remove(token);
    }
}

impl Default for TokenAuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TokenAuthPlugin {
    fn clone(&self) -> Self {
        Self {
            valid_tokens: self.valid_tokens.clone(),
        }
    }
}

#[async_trait]
impl AuthPlugin for TokenAuthPlugin {
    fn name(&self) -> &'static str {
        "token"
    }

    async fn verify(&self, token: &str) -> Result<bool> {
        let tokens = self.valid_tokens.read().unwrap();
        Ok(tokens.contains(token))
    }
}