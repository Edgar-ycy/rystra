/// 连接状态机
use std::sync::atomic::{AtomicU64, Ordering};

static CONNECTION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Authenticating,
    Ready,
    Closing,
}

pub struct ControlConnection {
    pub id: u64,
    pub client_id: Option<String>,
    pub state: ConnectionState,
}

impl ControlConnection {
    pub fn new() -> Self {
        Self {
            id: CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst),
            client_id: None,
            state: ConnectionState::Connecting,
        }
    }

    pub fn set_client_id(&mut self, client_id: String) {
        self.client_id = Some(client_id);
    }

    pub fn transition_to(&mut self, state: ConnectionState) {
        self.state = state;
    }

    pub fn is_ready(&self) -> bool {
        self.state == ConnectionState::Ready
    }
}

impl Default for ControlConnection {
    fn default() -> Self {
        Self::new()
    }
}