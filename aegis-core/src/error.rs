use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("rate limit exceeded")]
    RateLimited,

    #[error("IP address blocked: {0}")]
    IpBlocked(IpAddr),

    #[error("request rejected: {0}")]
    RequestRejected(String),
}
