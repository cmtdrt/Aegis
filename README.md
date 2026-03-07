# Aegis

A lightweight security layer for APIs, written in Rust.

Aegis provides reusable protection features — rate limiting, IP filtering, and request inspection — that can be deployed in two ways:

- **As a middleware** embedded directly inside your Axum API.
- **As a standalone reverse proxy** placed in front of any HTTP service.

## Architecture

```
aegis-core          Pure Rust security engine (framework-agnostic)
aegis-middleware    Tower Layer for Axum, wraps aegis-core
aegis-proxy         Standalone reverse proxy, uses aegis-core
```

All security logic lives in `aegis-core`. Both the middleware and the proxy reuse the same implementation.

## Usage

### Embed as middleware (Axum)

Add the dependency:

```toml
[dependencies]
aegis-middleware = { path = "aegis-middleware" }
```

Then plug it into your router:

```rust
use aegis_core::{AegisConfig, config::RateLimitConfig};
use aegis_middleware::AegisLayer;

let config = AegisConfig {
    rate_limit: Some(RateLimitConfig {
        max_requests: 100,
        window_secs: 60,
    }),
    ..Default::default()
};

let app = Router::new()
    .route("/", get(handler))
    .layer(AegisLayer::new(config));
```

Make sure to serve with `into_make_service_with_connect_info::<SocketAddr>()` so Aegis can resolve client IPs.

### Run as a reverse proxy

Configure `aegis.toml`:

```toml
listen = "0.0.0.0:3000"
upstream = "http://localhost:8080"

[aegis.rate_limit]
max_requests = 100
window_secs = 60

[aegis.inspection]
max_body_size = 1048576
blocked_patterns = ["<script>", "../"]
```

Then start the proxy:

```sh
cargo run -p aegis-proxy -- aegis.toml
```

All incoming requests are checked before being forwarded to the upstream service.

## Features

- **Rate limiting** — fixed-window counter per client IP.
- **IP filtering** — whitelist and/or blacklist.
- **Request inspection** — body size limit and blocked pattern detection (path, headers, body).
- **Logging** — structured traces via `tracing` (set `RUST_LOG=info`).

## License

MIT
