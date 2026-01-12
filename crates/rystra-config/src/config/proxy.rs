use crate::config::transport_kind::TransportKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    pub name: String,
    pub kind: TransportKind,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
}
