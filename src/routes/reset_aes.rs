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

use axum::{extract::State, Form};
use serde::Deserialize;

use crate::crypto;
use crate::db;
use crate::response::{error_response, success_response};
use crate::AppState;

#[derive(Deserialize)]
pub struct ResetAesForm {
    pub uuid: String,
    pub aes_key_hex: String,
}

/// POST /reset_aes — Reset the AES-256 key for an account.
/// Takes the current AES key in plain hex to authorize the operation.
/// Returns the new AES key.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ResetAesForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    // Parse UUID
    let uuid = form.uuid.parse()
        .map_err(|_| error_response(400, "invalid_uuid", "Invalid UUID format"))?;

    // Look up user in database
    let user = db::get_user_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))?;

    // Verify the provided AES key matches the stored one
    let current_hex = hex::encode(&user.aes_key);
    if current_hex != form.aes_key_hex {
        return Err(error_response(403, "auth_failed", "AES key does not match"));
    }

    // Generate a new AES key
    let new_key = crypto::generate_aes_key();

    // Update in database
    db::update_user_aes_key(&state.db, &uuid, &new_key)
        .await
        .map_err(|_e| error_response(500, "db_error", "Failed to update AES key"))?;

    let new_hex = hex::encode(new_key);
    let body = format!("aes_key_hex={}", new_hex);

    Ok(success_response(body))
}