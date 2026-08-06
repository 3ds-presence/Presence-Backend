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
use crate::routes::common::authenticate_aes_key;
use crate::validation;
use crate::AppState;

#[derive(Deserialize)]
pub struct ResetAesForm {
    pub uuid: String,
    pub aes_key_hex: String,
}

/// POST /`reset_aes` — Reset the AES-256 key (authorized by providing the current key).
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ResetAesForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let uuid = validation::validate_uuid(&form.uuid)?;
    validation::validate_aes_key_hex(&form.aes_key_hex)?;

    authenticate_aes_key(
        &state.db,
        &state.config.master_key,
        &uuid,
        &form.aes_key_hex,
        state.config.debug_mode,
    )
    .await?;

    let new_key = crypto::generate_aes_key();

    db::update_user_aes_key(&state.db, &state.config.master_key, &uuid, &new_key)
        .await
        .map_err(|_e| error_response(500, "db_error", "Failed to update AES key"))?;

    let new_hex = hex::encode(new_key);
    let body = format!("aes_key_hex={new_hex}");

    Ok(success_response(body))
}
