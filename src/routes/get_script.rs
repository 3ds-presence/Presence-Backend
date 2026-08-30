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
use crate::response::{error_response, success_response};
use crate::session::session_error_into_response;
use crate::validation;
use crate::AppState;

#[derive(Deserialize, Debug, Default)]
pub struct GetScriptForm {
    pub uuid: String,
    pub auth_hex: String,
    pub titleid: String,
}

/// POST /3ds/script — Fetch the RAM addresses file (`code.txt`) for a title.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<GetScriptForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth = Auth::new(&form.uuid, &form.auth_hex)?;
    let titleid = validation::validate_titleid(Some(form.titleid))?.ok_or_else(|| {
        error_response(400, "invalid_titleid", "titleid must be 16 hex characters")
    })?;

    // The exact message the 3DS signs: sha256(titleid=...) inside the auth envelope.
    let message = format!("titleid={titleid}");
    let fields = [message.as_str()];
    let counter = state
        .session_manager
        .verify_and_tick(&auth, &fields)
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode, Some(&auth.uuid)))?;

    // No code file for this title: still answer success with a "-" placeholder,
    // signed like the real payload, so the client knows the exchange went fine
    // but there is nothing to load.
    let code = state
        .activity_generator
        .get_3ds_code(&titleid)
        .unwrap_or_else(|| "-".to_string());

    // Server-side signature over the exact payload the 3DS received, bound to
    // the requested titleid and using the same counter as the verified request.
    // The 3DS recomputes this envelope with its AES key and checks it matches,
    // proving the code is authentic, unmodified, and not a stale replay for a
    // different title.
    let code_field = format!("titleid={titleid}&code={code}");
    let sig_hex = state
        .session_manager
        .sign_response(&auth, counter, &[code_field.as_str()])
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode, Some(&auth.uuid)))?;

    log::info!("evt=get_script uuid={} titleid={titleid}", auth.uuid);

    Ok(success_response(format!(
        "success=true&code={code}&sig_hex={sig_hex}"
    )))
}
