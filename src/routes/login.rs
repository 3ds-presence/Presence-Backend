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

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, Form};
use log::info;
use serde::Deserialize;

use crate::crypto;
use crate::db;
use crate::response::{error_response, success_response};
use crate::utils;
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

    let aes_key = crypto::decrypt_aes_key_at_rest(&user.aes_key, &state.config.master_key)
        .ok_or_else(|| error_response(500, "crypto_error", "Failed to decrypt AES key"))?;

    let client_ip = utils::net::extract_client_ip(&headers)
        .ok_or_else(|| error_response(400, "missing_ip", "Could not determine client IP address"))?;

    info!("evt=login_started uuid={uuid} ip={client_ip}");

    let nonce = state
        .session_manager
        .create_pending(uuid, aes_key, client_ip, state.config.max_clients_per_ip)
        .await
        .map_err(|e| {
            log::warn!("evt=rate_limited uuid={uuid} ip={client_ip} reason={e}");
            error_response(429, "rate_limited", e)
        })?;

    let body = format!("nonce={nonce}");

    Ok(success_response(body))
}

