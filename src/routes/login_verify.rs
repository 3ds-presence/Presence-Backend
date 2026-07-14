use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use crate::db;
use crate::error::error_response;
use crate::AppState;

#[derive(Deserialize)]
pub struct LoginVerifyForm {
    pub uuid: String,
    pub cipher_hex: String,
}

/// POST /login/verify — Prove possession of the AES key.
/// The client encrypts the nonce received from /login and sends it back.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginVerifyForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    if form.cipher_hex.is_empty() {
        return Err(error_response(400, "missing_field", "cipher_hex is required"));
    }

    let uuid = Uuid::parse_str(&form.uuid)
        .map_err(|_| error_response(400, "invalid_uuid", "Invalid UUID format"))?;

    // Get user from DB for access_token
    let user = db::get_user_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))?;

    // Verify the encrypted nonce and activate the session
    let nonce = state.session_manager
        .verify_and_activate(uuid, &form.cipher_hex, state.discord_rpc.rpc(), &user.access_token, state.config.activity_cooldown_secs)
        .await
        .map_err(|e| {
            error_response(403, "auth_failed", &format!("Verification failed: {}", e))
        })?;

    let body = format!("success=true&nonce={}", nonce);

    Ok(axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap())
}