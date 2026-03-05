use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use tower_layer::Layer;
use tower_service::Service;
use tracing::warn;

pub use aegis_core;
use aegis_core::{AegisConfig, AegisEngine, AegisError, AegisRequest};

/// Inserts Aegis security checks in front of a service.
#[derive(Clone)]
pub struct AegisLayer {
    engine: Arc<AegisEngine>,
}

impl AegisLayer {
    pub fn new(config: AegisConfig) -> Self {
        Self {
            engine: Arc::new(AegisEngine::new(config)),
        }
    }
}

impl<S> Layer<S> for AegisLayer {
    type Service = AegisService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AegisService {
            inner,
            engine: self.engine.clone(),
        }
    }
}

/// Evaluates every request through the Aegis engine.
#[derive(Clone)]
pub struct AegisService<S> {
    inner: S,
    engine: Arc<AegisEngine>,
}

impl<S> Service<Request<Body>> for AegisService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let engine = self.engine.clone();

        // Replace self.inner with a fresh clone.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let remote_ip = extract_client_ip(&request);

            let aegis_request = AegisRequest {
                method: request.method().to_string(),
                path: request.uri().path().to_string(),
                headers: request
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
                    .collect(),
                body: None, // The middleware never consumes the body.
                remote_ip,
            };

            match engine.evaluate(&aegis_request) {
                Ok(()) => inner.call(request).await,
                Err(err) => Ok(error_to_response(err)),
            }
        })
    }
}


/// Resolve the client IP from `X-Forwarded-For`, then `ConnectInfo`, with a fallback to `0.0.0.0`.
fn extract_client_ip(request: &Request<Body>) -> IpAddr {
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(value) = xff.to_str() {
            if let Some(first) = value.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    if let Some(connect_info) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        return connect_info.0.ip();
    }

    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

fn error_to_response(err: AegisError) -> Response {
    let (status, message) = match &err {
        AegisError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded"),
        AegisError::IpBlocked(_) => (StatusCode::FORBIDDEN, "access denied"),
        AegisError::RequestRejected(_) => (StatusCode::BAD_REQUEST, "request rejected"),
    };

    warn!(status = %status, error = %err, "Request blocked");

    let body = serde_json::json!({
        "error": message,
        "detail": err.to_string(),
    });

    (status, axum::Json(body)).into_response()
}
