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

use crate::auth::Auth;
use crate::db;
use crate::response::{error_response, success_response};
use crate::routes::common::authenticate_aes_key;
use crate::validation;
use crate::AppState;

#[derive(Deserialize)]
pub struct DeleteForm {
    pub uuid: String,
    pub aes_key_hex: String,
}

/// POST /account/delete — Permanently delete the user's account and all associated data.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, Response> {
    let uuid = validation::validate_uuid(&form.uuid)?;
    let supplied_key_hex = validation::validate_aes_key_hex(&form.aes_key_hex)?.to_owned();
    let debug = state.config.debug_mode;

    authenticate_aes_key(
        &state.db,
        &state.config.master_key,
        &uuid,
        &supplied_key_hex,
        debug,
    )
    .await?;

    let auth = Auth::from_uuid(uuid, supplied_key_hex);
    let _ = state
        .session_manager
        .stop_activity(&auth, state.config.activity_cooldown_secs)
        .await;

    db::delete_user(&state.db, &uuid).await.map_err(|e| {
        let msg = if debug {
            format!("{e}")
        } else {
            "Failed to delete account".to_string()
        };
        error_response(500, "db_error", &msg)
    })?;

    log::info!("account deleted: {uuid}");
    Ok(success_response("success=true".to_string()))
}
