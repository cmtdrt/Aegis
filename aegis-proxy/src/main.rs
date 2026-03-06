use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use http_body_util::BodyExt;
use serde::Deserialize;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use aegis_core::{AegisConfig, AegisEngine, AegisError, AegisRequest};

#[derive(Deserialize)]
struct ProxyConfig {
    listen: String,
    upstream: String,
    #[serde(default = "default_max_body_size")]
    max_body_size: usize,
    aegis: AegisConfig,
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10 MB
}


struct ProxyState {
    engine: AegisEngine,
    upstream: String,
    max_body_size: usize,
    client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "aegis.toml".into());

    let config_str =
        std::fs::read_to_string(&config_path).expect("failed to read configuration file");
    let config: ProxyConfig =
        toml::from_str(&config_str).expect("failed to parse configuration file");

    let state = Arc::new(ProxyState {
        engine: AegisEngine::new(config.aegis),
        upstream: config.upstream.trim_end_matches('/').to_string(),
        max_body_size: config.max_body_size,
        client: reqwest::Client::new(),
    });

    let app = Router::new()
        .fallback(handle_proxy)
        .with_state(state);

    let addr: SocketAddr = config.listen.parse().expect("invalid listen address");
    info!("Aegis proxy listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}


async fn handle_proxy(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    let remote_ip = resolve_client_ip(&request, addr);
    let (parts, body) = request.into_parts();

    // Read the full body so we can inspect it and forward it.
    let body_bytes = match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            if bytes.len() > state.max_body_size {
                return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
            }
            bytes
        }
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };

    // Build the framework-agnostic request and run it through the engine.
    let aegis_request = AegisRequest {
        method: parts.method.to_string(),
        path: parts.uri.path().to_string(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
            .collect(),
        body: if body_bytes.is_empty() {
            None
        } else {
            Some(body_bytes.to_vec())
        },
        remote_ip,
    };

    if let Err(err) = state.engine.evaluate(&aegis_request) {
        return aegis_error_response(err);
    }

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_url = format!("{}{}", state.upstream, path_and_query);

    let mut forwarded_headers = HeaderMap::new();
    for (key, value) in &parts.headers {
        if !is_hop_by_hop(key.as_str()) && key != http::header::HOST {
            forwarded_headers.insert(key.clone(), value.clone());
        }
    }

    // Append to an existing X-Forwarded-For or create a new one.
    let xff_value = match parts.headers.get("x-forwarded-for") {
        Some(existing) => format!(
            "{}, {}",
            existing.to_str().unwrap_or_default(),
            remote_ip
        ),
        None => remote_ip.to_string(),
    };
    if let Ok(val) = http::HeaderValue::from_str(&xff_value) {
        forwarded_headers.insert("x-forwarded-for", val);
    }

    let mut builder = state
        .client
        .request(parts.method, &upstream_url)
        .headers(forwarded_headers);

    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.to_vec());
    }

    match builder.send().await {
        Ok(upstream_resp) => build_response(upstream_resp).await,
        Err(err) => {
            error!(error = %err, "upstream request failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

fn resolve_client_ip(request: &Request<Body>, fallback: SocketAddr) -> IpAddr {
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(value) = xff.to_str() {
            if let Some(first) = value.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    fallback.ip()
}

async fn build_response(upstream: reqwest::Response) -> Response {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let body = upstream.bytes().await.unwrap_or_default();

    let mut response = (status, body).into_response();
    for (key, value) in headers.iter() {
        if !is_hop_by_hop(key.as_str()) {
            response.headers_mut().insert(key.clone(), value.clone());
        }
    }
    response
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn aegis_error_response(err: AegisError) -> Response {
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

// Unused placeholder to silence warning – will be used once the `resolve_client_ip`
// fallback goes through `ConnectInfo` extensions.
const _: () = {
    fn _assert_ip_unspecified() {
        let _ = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    }
};
