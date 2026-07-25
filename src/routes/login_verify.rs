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

use crate::auth::Auth;
use crate::db;
use crate::response::error_response;
use crate::response::success_response;
use crate::session::session_error_into_response;
use crate::validation;
use crate::AppState;
use activity_generator::UserInfo;

#[derive(Deserialize)]
pub struct LoginVerifyForm {
    pub uuid: String,
    pub cipher_hex: String,
    pub mii: Option<String>,
}

/// POST /login/verify — Prove AES key possession by encrypting the nonce.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginVerifyForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let uuid = validation::validate_uuid(&form.uuid)?;
    let cipher_hex = validation::validate_cipher_hex(&form.cipher_hex)?;
    let mii = validation::validate_mii(form.mii).unwrap_or(None);

    let auth = Auth::from_uuid(uuid, cipher_hex.to_string());

    let user = db::get_user_by_uuid(&state.db, &auth.uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))?;

    let user_info = mii.map(|mii| {
        let mii_name = crate::utils::mii_utils::get_mii_name(&mii).ok();
        UserInfo {
            mii: Some(mii),
            mii_name,
        }
    });

    state
        .session_manager
        .verify_and_activate(
            &auth,
            state.discord_rpc.rpc(),
            &user.access_token,
            state.config.activity_cooldown_secs,
            user_info,
        )
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode))?;

    Ok(success_response("success=true"))
}
