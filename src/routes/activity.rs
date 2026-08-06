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
use axum::response::Response;
use axum::{extract::State, Form};
use serde::Deserialize;

use crate::auth::Auth;
use crate::response::{error_response, success_response, AppError};
use crate::session::session_error_into_response;
use crate::validation;
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
) -> Result<Response, Response> {
    let auth = Auth::new(&form.uuid, &form.auth_hex)?;

    let titleid = validation::validate_titleid(form.titleid)?;
    let name = validation::validate_name(form.name)?;
    let publisher = validation::validate_publisher(form.publisher)?;
    let extra = validation::validate_extra(form.extra)?;

    let game_info = generate_game_info(titleid, name, publisher, extra.as_ref())?;

    state
        .session_manager
        .update_activity(&state, &auth, game_info, extra)
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode))?;

    Ok(success_response("success=true"))
}

/// Build an optional `GameInfo` from validated form fields.
///
/// If at least one of `titleid`, `name`, `publisher` or `extra` is present,
/// then all of `titleid`, `name` and `publisher` must be present too.
/// Returns `Ok(None)` when all fields are absent (only `uuid` + `auth_hex`).
fn generate_game_info(
    titleid: Option<String>,
    name: Option<String>,
    publisher: Option<String>,
    extra: Option<&String>,
) -> Result<Option<GameInfo>, AppError> {
    if titleid.is_some() || name.is_some() || publisher.is_some() || extra.is_some() {
        let titleid_val = titleid.ok_or_else(|| incomplete_fields_error())?;
        let name_val = name.ok_or_else(|| incomplete_fields_error())?;
        let publisher_val = publisher.ok_or_else(|| incomplete_fields_error())?;
        Ok(Some(GameInfo {
            title_id: titleid_val,
            name: name_val,
            publisher: publisher_val,
        }))
    } else {
        Ok(None)
    }
}

/// Build the shared "incomplete fields" error.
fn incomplete_fields_error() -> AppError {
    AppError(Box::new(error_response(
        400,
        "incomplete_fields",
        "titleid, name and publisher must all be provided together",
    )))
}

/// POST /activity/heartbeat — Keep session alive without changing activity.
pub async fn heartbeat_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ActivityForm>,
) -> Result<Response, Response> {
    let auth = Auth::new(&form.uuid, &form.auth_hex)?;

    state
        .session_manager
        .heartbeat(&auth, state.config.activity_cooldown_secs)
        .await
        .map_err(|e| session_error_into_response(e, state.config.debug_mode))?;

    Ok(success_response("success=true"))
}
