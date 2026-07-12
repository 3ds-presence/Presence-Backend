use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use axum::response::IntoResponse;

use crate::error::error_response;
use crate::AppState;

#[derive(Deserialize, Debug, Default)]
pub struct LogoutForm {
    pub uuid: String,
    pub counter: String,  // u64 as string for flexibility
    pub auth_hex: String,
}

/// POST /logout — Stop the Discord activity for an active session and remove it.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LogoutForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    if form.uuid.is_empty() || form.auth_hex.is_empty() || form.counter.is_empty() {
        return Err(error_response(400, "missing_field", "uuid, counter, and auth_hex are required"));
    }

    let uuid = Uuid::parse_str(&form.uuid)
        .map_err(|_| error_response(400, "invalid_uuid", "Invalid UUID format"))?;

    let counter: u64 = form.counter.parse()
        .map_err(|_| error_response(400, "invalid_counter", "Counter must be a positive integer"))?;

    // Stop the activity via session manager
    state.session_manager
        .stop_activity(uuid, counter, &form.auth_hex, state.config.activity_cooldown_secs)
        .await
        .map_err(|e| e.into_response())?;

    let body = "success=true".to_string();

    Ok(axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap())
}