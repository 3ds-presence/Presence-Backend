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


use std::net::IpAddr;
use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, Form};
use log::info;
use serde::Deserialize;

use crate::db;
use crate::response::{error_response, success_response};
use crate::validation;
use crate::AppState;

#[derive(Deserialize)]
pub struct LoginForm {
    pub uuid: String,
}

/// POST /login — Start the authentication challenge.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let uuid = validation::validate_uuid(&form.uuid)?;

    let user = db::get_user_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))?;

    if user.aes_key.len() != 32 {
        return Err(error_response(500, "crypto_error", "Invalid AES key in database"));
    }
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&user.aes_key);

    let client_ip = extract_real_ip(&headers)
        .map_err(|e| error_response(400, "missing_ip", e))?;

    info!("Login request for UUID {} from IP {}", uuid, client_ip);

    let nonce = state.session_manager
        .create_pending(uuid, aes_key, client_ip, state.config.max_clients_per_ip)
        .await
        .map_err(|e| error_response(429, "rate_limited", e))?;

    let body = format!("nonce={}", nonce);

    Ok(success_response(body))
}

/// Extract client IP from reverse proxy headers (X-Real-IP, then X-Forwarded-For).
fn extract_real_ip(headers: &HeaderMap) -> Result<IpAddr, &'static str> {
    // Try X-Real-IP first
    if let Some(value) = headers.get("x-real-ip") {
        if let Ok(s) = value.to_str() {
            if let Ok(ip) = s.parse::<IpAddr>() {
                return Ok(ip);
            }
        }
    }

    // Fallback to X-Forwarded-For
    if let Some(value) = headers.get("x-forwarded-for") {
        if let Ok(s) = value.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
        }
    }

    Err("Could not determine client IP address")
}