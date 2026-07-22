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

use activity_generator::UserInfo;
use crate::auth::Auth;
use crate::db;
use crate::response::error_response;
use crate::response::success_response;
use crate::AppState;
use crate::session::session_error_into_response;

#[derive(Deserialize)]
pub struct LoginVerifyForm {
    pub uuid: String,
    pub cipher_hex: String,
    pub mii: Option<String>,
}

/// POST /login/verify — Prove possession of the AES key.
/// The client encrypts the nonce received from /login and sends it back.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginVerifyForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth = Auth::new(&form.uuid, &form.cipher_hex)?;

    // Get user from DB for access_token
    let user = db::get_user_by_uuid(&state.db, &auth.uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))?;

    // Build optional UserInfo from the mii query parameter
    let user_info = form.mii.map(|mii| {
        let mii_name = crate::utils::mii_utils::get_mii_name(&mii).ok();
        UserInfo {
            mii: Some(mii),
            mii_name,
        }
    });

    // Verify the encrypted nonce and activate the session
    state.session_manager
        .verify_and_activate(&auth, state.discord_rpc.rpc(), &user.access_token, state.config.activity_cooldown_secs, user_info)
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode))?;

    Ok(success_response("success=true"))
}