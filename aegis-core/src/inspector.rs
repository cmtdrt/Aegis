use crate::config::InspectionConfig;
use crate::error::AegisError;
use crate::request::AegisRequest;

pub struct RequestInspector {
    config: InspectionConfig,
}

impl RequestInspector {
    pub fn new(config: InspectionConfig) -> Self {
        Self { config }
    }

    /// Run all configured inspection rules against the request.
    pub fn inspect(&self, request: &AegisRequest) -> Result<(), AegisError> {
        self.check_body_size(request)?;
        self.check_blocked_patterns(request)?;
        Ok(())
    }

    fn check_body_size(&self, request: &AegisRequest) -> Result<(), AegisError> {
        if let (Some(max), Some(body)) = (self.config.max_body_size, &request.body) {
            if body.len() > max {
                return Err(AegisError::RequestRejected(format!(
                    "body size {} exceeds maximum {}",
                    body.len(),
                    max
                )));
            }
        }
        Ok(())
    }

    fn check_blocked_patterns(&self, request: &AegisRequest) -> Result<(), AegisError> {
        for pattern in &self.config.blocked_patterns {
            if request.path.contains(pattern.as_str()) {
                return Err(AegisError::RequestRejected(format!(
                    "blocked pattern '{}' found in path",
                    pattern
                )));
            }

            for value in request.headers.values() {
                if value.contains(pattern.as_str()) {
                    return Err(AegisError::RequestRejected(format!(
                        "blocked pattern '{}' found in headers",
                        pattern
                    )));
                }
            }

            if let Some(body) = &request.body {
                if let Ok(text) = std::str::from_utf8(body) {
                    if text.contains(pattern.as_str()) {
                        return Err(AegisError::RequestRejected(format!(
                            "blocked pattern '{}' found in body",
                            pattern
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}
