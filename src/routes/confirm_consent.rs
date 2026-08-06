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

use axum::response::Response;
use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto;
use crate::db::{self, CreateUserParams};
use crate::response::{error_response, success_response};
use crate::AppState;

#[derive(Deserialize)]
pub struct ConsentForm {
    pub temp_token: String,
}

/// POST /confirm-consent — User has accepted the privacy policy, create account.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ConsentForm>,
) -> Result<Response, Response> {
    let temp_token = Uuid::parse_str(&form.temp_token).map_err(|_| {
        error_response(400, "invalid_temp_token", "Invalid temp_token format")
    })?;

    let (discord_id, access_token, refresh_token, expires_at) = state
        .session_manager
        .confirm_consent(&temp_token)
        .await
        .map_err(|_| {
            error_response(
                400,
                "consent_expired",
                "Consent session expired or not found. Please login again.",
            )
        })?;

    let now = crypto::now_secs();
    let uuid = Uuid::new_v4();
    let aes_key = crypto::generate_aes_key();

    let debug = state.config.debug_mode;
    db::create_user(CreateUserParams {
        db: &state.db,
        master_key: &state.config.master_key,
        uuid: &uuid,
        discord_id: &discord_id,
        aes_key: &aes_key,
        access_token: &access_token,
        refresh_token: &refresh_token,
        token_expires_at: expires_at,
        created_at: now,
    })
    .await
    .map_err(|e| {
        let msg = if debug {
            format!("Failed to create user: {e}")
        } else {
            "Failed to create user".to_string()
        };
        error_response(500, "db_error", &msg)
    })?;

    let aes_hex = hex::encode(aes_key);
    let body = format!("uuid={uuid}&aes_key_hex={aes_hex}");
    log::info!("new user {uuid} created after accepting consent");
    Ok(success_response(body))
}