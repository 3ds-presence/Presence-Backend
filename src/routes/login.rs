use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use crate::db;
use crate::error::error_response;
use crate::AppState;

#[derive(Deserialize)]
pub struct LoginForm {
    pub uuid: String,
}

/// POST /login — Start the authentication challenge.
/// Returns a nonce that the client must encrypt with AES to prove identity.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    // Parse UUID
    let uuid = Uuid::parse_str(&form.uuid)
        .map_err(|_| error_response(400, "invalid_uuid", "Invalid UUID format"))?;

    // Look up user in database
    let user = db::get_user_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))?;

    // Convert aes_key from DB to [u8; 32]
    if user.aes_key.len() != 32 {
        return Err(error_response(500, "crypto_error", "Invalid AES key in database"));
    }
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&user.aes_key);

    // Get client IP address
    // In axum 0.8, we can get it from the extension.
    // For now, we use a placeholder since extracting the real IP requires middleware.
    // The client_ip will be set by middleware in main.rs.
    let client_ip = "0.0.0.0".parse().unwrap(); // Will be overridden by middleware

    // Create pending session with nonce challenge
    let nonce = state.session_manager
        .create_pending(uuid, aes_key, client_ip, state.config.max_clients_per_ip)
        .await
        .map_err(|e| error_response(429, "rate_limited", e))?;

    let body = format!("nonce={}", nonce);

    Ok(axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap())
}