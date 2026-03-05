use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AegisConfig {
    pub rate_limit: Option<RateLimitConfig>,
    pub ip_filter: Option<IpFilterConfig>,
    pub inspection: Option<InspectionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_requests: u64,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterConfig {
    #[serde(default)]
    pub whitelist: Vec<IpAddr>,
    #[serde(default)]
    pub blacklist: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionConfig {
    pub max_body_size: Option<usize>,
    #[serde(default)]
    pub blocked_patterns: Vec<String>,
}
