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

use activity_generator::UserInfo;
use crate::auth::Auth;
use crate::crypto;
use crate::response::{error_response, success_response};
use crate::routes::common::fetch_user_or_404;
use crate::session::session_error_into_response;
use crate::utils::mii_utils;
use crate::validation;
use crate::AppState;

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
) -> Result<Response, Response> {
    let uuid = validation::validate_uuid(&form.uuid)?;
    let cipher_hex = validation::validate_cipher_hex(&form.cipher_hex)?;
    let mii = validation::validate_mii(form.mii)?;

    let auth = Auth::from_uuid(uuid, cipher_hex.to_string());

    let user = fetch_user_or_404(&state.db, &auth.uuid).await?;

    // The access token is stored encrypted at rest — decrypt it before use.
    let access_token = crypto::decrypt_string_at_rest(&user.access_token, &state.config.master_key)
        .ok_or_else(|| error_response(500, "crypto_error", "Failed to decrypt access token"))?;

    let user_info = mii.map(|mii| {
        let mii_name = mii_utils::get_mii_name(&mii).ok();
        UserInfo {
            mii: Some(mii),
            mii_name,
        }
    });

    log::debug!("evt=login_verify uuid={}", auth.uuid);
    state
        .session_manager
        .verify_and_activate(
            &auth,
            state.discord_rpc.rpc(),
            &access_token,
            state.config.activity_cooldown_secs,
            user_info,
        )
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode, Some(&auth.uuid)))?;

    log::info!("evt=session_activated uuid={}", auth.uuid);
    Ok(success_response("success=true"))
}