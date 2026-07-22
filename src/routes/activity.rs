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

use activity_generator::info::GameInfo;
use axum::{extract::State, Form};
use serde::Deserialize;

use crate::auth::Auth;
use crate::response::{error_response, success_response};
use crate::session::session_error_into_response;
use crate::AppState;

#[derive(Deserialize, Debug, Default)]
pub struct ActivityForm {
    pub uuid: String,
    pub auth_hex: String,
    pub titleid: Option<String>,
    pub name: Option<String>,
    pub publisher: Option<String>,
    pub extra: Option<String>,
}

/// POST /activity/set — Update the Discord activity.
pub async fn set_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ActivityForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let titleid = match &form.titleid {
        Some(t) => t.clone(),
        None => return Err(error_response(400, "missing_field", "titleid is required")),
    };

    if titleid.chars().count() != 16 {
        return Err(error_response(400, "invalid_titleid", "titleid must be exactly 16 characters long"));
    }

    if form.name.is_none() || form.publisher.is_none() {
        return Err(error_response(400, "missing_field", "name and publisher are required"));
    }

    let auth = Auth::new(&form.uuid, &form.auth_hex)?;
    let game_info = GameInfo {
        title_id: titleid,
        name: form.name.clone().unwrap_or_default(),
        publisher: form.publisher.clone().unwrap_or_default(),
    };

    state.session_manager
        .update_activity(&state, &auth, game_info, form.extra)
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode))?;

    Ok(success_response("success=true"))
}

/// POST /activity/heartbeat — Keep session alive without changing activity.
pub async fn heartbeat_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ActivityForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth = Auth::new(&form.uuid, &form.auth_hex)?;

    state.session_manager
        .heartbeat(&auth, state.config.activity_cooldown_secs)
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode))?;

    Ok(success_response("success=true"))
}