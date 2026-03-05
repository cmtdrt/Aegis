use tracing::{info, warn};

use crate::config::AegisConfig;
use crate::error::AegisError;
use crate::inspector::RequestInspector;
use crate::ip_filter::IpFilter;
use crate::rate_limiter::RateLimiter;
use crate::request::AegisRequest;

/// Central evaluation engine that orchestrates all security checks.
pub struct AegisEngine {
    rate_limiter: Option<RateLimiter>,
    ip_filter: Option<IpFilter>,
    inspector: Option<RequestInspector>,
}

impl AegisEngine {
    pub fn new(config: AegisConfig) -> Self {
        info!(
            rate_limit = config.rate_limit.is_some(),
            ip_filter = config.ip_filter.is_some(),
            inspection = config.inspection.is_some(),
            "Aegis engine initialised"
        );

        Self {
            rate_limiter: config.rate_limit.map(RateLimiter::new),
            ip_filter: config.ip_filter.map(IpFilter::new),
            inspector: config.inspection.map(RequestInspector::new),
        }
    }

    /// Evaluate the request against every enabled security rule.
    /// Returns `Ok(())` when the request is allowed through.
    pub fn evaluate(&self, request: &AegisRequest) -> Result<(), AegisError> {
        info!(
            method = %request.method,
            path = %request.path,
            ip = %request.remote_ip,
            "Evaluating request"
        );

        if let Some(filter) = &self.ip_filter {
            filter.check(request.remote_ip).inspect_err(|e| {
                warn!(error = %e, "Blocked by IP filter");
            })?;
        }

        if let Some(limiter) = &self.rate_limiter {
            limiter
                .check(&request.remote_ip.to_string())
                .inspect_err(|e| {
                    warn!(ip = %request.remote_ip, error = %e, "Blocked by rate limiter");
                })?;
        }

        if let Some(inspector) = &self.inspector {
            inspector.inspect(request).inspect_err(|e| {
                warn!(error = %e, "Blocked by request inspector");
            })?;
        }

        info!("Request allowed");
        Ok(())
    }
}
