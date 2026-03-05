use std::collections::HashMap;
use std::net::IpAddr;

/// Framework-agnostic representation of an incoming HTTP request.
#[derive(Debug, Clone)]
pub struct AegisRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub remote_ip: IpAddr,
}
