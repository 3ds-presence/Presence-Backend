use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;

use axum::response::IntoResponse;

use crate::auth::Auth;
use crate::response::{error_response, success_response};
use crate::AppState;

#[derive(Deserialize, Debug, Default)]
pub struct ActivityForm {
    pub uuid: String,
    pub auth_hex: String,
    pub titleid: String,
}

/// POST /activity/set — Update the Discord activity.
pub async fn set_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ActivityForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    if form.titleid.is_empty() {
        return Err(error_response(400, "missing_field", "titleid is required"));
    }

    if form.titleid.chars().count() != 16 {
        return Err(error_response(400, "invalid_titleid", "titleid must be exactly 16 characters long"));
    }

    let auth = Auth::new(&form.uuid, &form.auth_hex)?;
    let titleid = form.titleid.as_str();

    state.session_manager
        .update_activity(&state, &auth, titleid)
        .await
        .map_err(|e| e.into_response())?;

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
        .map_err(|e| e.into_response())?;

    Ok(success_response("success=true"))
}