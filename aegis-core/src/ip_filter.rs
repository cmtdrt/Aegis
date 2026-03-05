use std::net::IpAddr;

use crate::config::IpFilterConfig;
use crate::error::AegisError;

pub struct IpFilter {
    config: IpFilterConfig,
}

impl IpFilter {
    pub fn new(config: IpFilterConfig) -> Self {
        Self { config }
    }

    /// Reject the IP if it is blacklisted or, when a whitelist is defined,
    /// not present in the whitelist.
    pub fn check(&self, ip: IpAddr) -> Result<(), AegisError> {
        if !self.config.whitelist.is_empty() && !self.config.whitelist.contains(&ip) {
            return Err(AegisError::IpBlocked(ip));
        }

        if self.config.blacklist.contains(&ip) {
            return Err(AegisError::IpBlocked(ip));
        }

        Ok(())
    }
}
