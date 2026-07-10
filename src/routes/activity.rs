use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;

#[derive(Deserialize, Debug, Default)]
pub struct ActivityForm {
    pub uuid: String,
    pub counter: String,  // u64 as string for flexibility
    pub auth_hex: String,
    pub state: Option<String>,
    pub details: Option<String>,
    pub activity_type: Option<String>, // u8 as string
}

/// POST /activity — Update the Discord activity or stop it.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ActivityForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    if form.uuid.is_empty() || form.auth_hex.is_empty() || form.counter.is_empty() {
        return Err(super::register::error_response(400, "missing_field", "uuid, counter, and auth_hex are required"));
    }

    let uuid = Uuid::parse_str(&form.uuid)
        .map_err(|_| super::register::error_response(400, "invalid_uuid", "Invalid UUID format"))?;

    let counter: u64 = form.counter.parse()
        .map_err(|_| super::register::error_response(400, "invalid_counter", "Counter must be a positive integer"))?;

    let activity_type: Option<u8> = match &form.activity_type {
        Some(t) => Some(t.parse().map_err(|_|
            super::register::error_response(400, "invalid_activity_type", "activity_type must be 0-255")
        )?),
        None => None,
    };

    let state_str = form.state.as_deref();
    let details_str = form.details.as_deref();

    // Update activity in session manager
    state.session_manager
        .update_activity(
            uuid,
            counter,
            &form.auth_hex,
            state_str,
            details_str,
            activity_type,
            state.config.activity_cooldown_secs,
        )
        .await
        .map_err(|e| {
            let msg = format!("{}", e);
            if msg.contains("session not found") || msg.contains("pending verification") {
                super::register::error_response(401, "session_expired", "Session expired or not found. Please re-login.")
            } else if msg.contains("replay") {
                super::register::error_response(403, "replay_detected", &msg)
            } else if msg.contains("cooldown") {
                super::register::error_response(429, "cooldown", &msg)
            } else if msg.contains("auth") {
                super::register::error_response(403, "auth_failed", &msg)
            } else {
                super::register::error_response(400, "error", &msg)
            }
        })?;

    let body = "success=true".to_string();

    Ok(axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap())
}