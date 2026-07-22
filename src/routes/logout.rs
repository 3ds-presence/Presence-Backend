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
use crate::response::success_response;
use crate::session::session_error_into_response;
use crate::AppState;

#[derive(Deserialize, Debug, Default)]
pub struct LogoutForm {
    pub uuid: String,
    pub auth_hex: String,
}

/// POST /logout — Stop the Discord activity for an active session and remove it.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LogoutForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth = Auth::new(&form.uuid, &form.auth_hex)?;

    // Stop the activity via session manager
    state.session_manager
        .stop_activity(&auth, 0)
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode))?;

    Ok(success_response("success=true"))
}