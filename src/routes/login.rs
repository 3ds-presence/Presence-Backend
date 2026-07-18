use std::net::IpAddr;
use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, Form};
use log::info;
use serde::Deserialize;

use crate::db;
use crate::response::{error_response, success_response};
use crate::AppState;

#[derive(Deserialize)]
pub struct LoginForm {
    pub uuid: String,
}

/// POST /login — Start the authentication challenge.
/// Returns a nonce that the client must encrypt with AES to prove identity.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    // Parse UUID
    let uuid = form.uuid.parse()
        .map_err(|_| error_response(400, "invalid_uuid", "Invalid UUID format"))?;

    // Look up user in database
    let user = db::get_user_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))?;

    // Convert aes_key from DB to [u8; 32]
    if user.aes_key.len() != 32 {
        return Err(error_response(500, "crypto_error", "Invalid AES key in database"));
    }
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&user.aes_key);

    // Extract real client IP from headers set by reverse proxy
    let client_ip = extract_real_ip(&headers)
        .map_err(|e| error_response(400, "missing_ip", e))?;

    info!("Login request for UUID {} from IP {}", uuid, client_ip);

    // Create pending session with nonce challenge
    let nonce = state.session_manager
        .create_pending(uuid, aes_key, client_ip, state.config.max_clients_per_ip)
        .await
        .map_err(|e| error_response(429, "rate_limited", e))?;

    let body = format!("nonce={}", nonce);

    Ok(success_response(body))
}

/// Extract the real client IP address from request headers set by the
/// reverse proxy (nginx).
///
/// Priority:
/// 1. `X-Real-IP` (set by the reverse proxy)
/// 2. `X-Forwarded-For` (first IP in the comma-separated list, fallback)
///
/// Returns an error if no valid IP header is found.
fn extract_real_ip(headers: &HeaderMap) -> Result<IpAddr, &'static str> {
    // 1. Try X-Real-IP (set by the reverse proxy)
    if let Some(value) = headers.get("x-real-ip") {
        if let Ok(s) = value.to_str() {
            if let Ok(ip) = s.parse::<IpAddr>() {
                return Ok(ip);
            }
        }
    }

    // 2. Fallback to X-Forwarded-For (first IP in the list)
    if let Some(value) = headers.get("x-forwarded-for") {
        if let Ok(s) = value.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
        }
    }

    // No valid IP found in any header
    Err("Could not determine client IP address")
}