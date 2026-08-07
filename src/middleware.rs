// 3DS Presence — Discord Rich Presence for Nintendo 3DS
// Copyright (C) 2026 3DS Presence - LeonLeBreton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use axum::middleware::Next;
use uuid::Uuid;

use crate::logging::{mask_body, RequestCtx, REQUEST_CTX};
use crate::utils;

/// Response header carrying the request ID so clients (and Nginx logs) can
/// correlate with the backend logs.
pub const X_REQUEST_ID: &str = "x-request-id";

const BODY_LOG_LIMIT: usize = 32 * 1024;

/// Log every request with a unique `req_id`, client IP, status and duration.
/// The `req_id` is propagated to every log line emitted while the request is
/// handled (via the task-local context).
/// Level `debug` additionally logs the (sensitive-masked) request body.
pub async fn request_logger(mut req: Request<Body>, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let ip = utils::net::extract_client_ip(req.headers()).map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
    let req_id = Uuid::new_v4().to_string();

    let body_snapshot = if log::log_enabled!(log::Level::Debug) {
        let (parts, body) = req.into_parts();
        match axum::body::to_bytes(body, BODY_LOG_LIMIT).await {
            Ok(bytes) => {
                let masked = mask_body(&String::from_utf8_lossy(&bytes));
                req = Request::from_parts(parts, Body::from(bytes));
                Some(masked)
            }
            Err(e) => {
                log::debug!("evt=request_body_read_failed error={e}");
                req = Request::from_parts(parts, Body::empty());
                None
            }
        }
    } else {
        None
    };

    let ctx = RequestCtx {
        req_id: req_id.clone(),
        ip: ip.clone(),
        path: path.clone(),
    };

    // Run the handler inside the scope so the formatter enriches every log
    // line (including the request line itself) with req_id/ip/path.
    let response = REQUEST_CTX
        .scope(ctx, async move {
            let response = next.run(req).await;
            let status = response.status().as_u16();
            let dur_ms = start.elapsed().as_millis();

            log::info!("evt=request method={method} path={path} status={status} dur_ms={dur_ms}");
            if let Some(body) = body_snapshot {
                log::debug!("evt=request_body method={method} path={path} body=\"{body}\"");
            }
            response
        })
        .await;

    let mut response = response;
    if let Ok(value) = req_id.parse::<axum::http::HeaderValue>() {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    response
}

