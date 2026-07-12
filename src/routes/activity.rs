use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use axum::response::IntoResponse;

use crate::error::error_response;
use crate::AppState;

#[derive(Deserialize, Debug, Default)]
pub struct ActivityForm {
    pub uuid: String,
    pub auth_hex: String,
    pub titleid: String,
}

/// POST /activity — Update the Discord activity or stop it.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ActivityForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    if form.uuid.is_empty() || form.auth_hex.is_empty() || form.titleid.is_empty() {
        return Err(error_response(400, "missing_field", "uuid, auth_hex, and titleid are required"));
    }

    if form.titleid.chars().count() != 16 {
        return Err(error_response(400, "invalid_titleid", "titleid must be exactly 16 characters long"));
    }

    let uuid = Uuid::parse_str(&form.uuid)
        .map_err(|_| error_response(400, "invalid_uuid", "Invalid UUID format"))?;

    let titleid = form.titleid.as_str();

    // Update activity in session manager
    state.session_manager
        .update_activity(
            &state,
            uuid,
            &form.auth_hex,
            titleid,
        )
        .await
        .map_err(|e| e.into_response())?;

    let body = "success=true".to_string();

    Ok(axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap())
}