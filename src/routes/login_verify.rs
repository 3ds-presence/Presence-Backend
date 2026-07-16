use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;

use activity_generator::UserInfo;
use crate::auth::Auth;
use crate::db;
use crate::response::error_response;
use crate::response::success_response;
use crate::AppState;

#[derive(Deserialize)]
pub struct LoginVerifyForm {
    pub uuid: String,
    pub cipher_hex: String,
    pub mii: Option<String>,
}

/// POST /login/verify — Prove possession of the AES key.
/// The client encrypts the nonce received from /login and sends it back.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginVerifyForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth = Auth::new(&form.uuid, &form.cipher_hex)?;

    // Get user from DB for access_token
    let user = db::get_user_by_uuid(&state.db, &auth.uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))?;

    // Build optional UserInfo from the mii query parameter
    let user_info = form.mii.map(|mii| UserInfo {
        mii: Some(mii),
        mii_name: None,
    });

    // Verify the encrypted nonce and activate the session
    let nonce = state.session_manager
        .verify_and_activate(&auth, state.discord_rpc.rpc(), &user.access_token, state.config.activity_cooldown_secs, user_info)
        .await
        .map_err(|e| {
            error_response(403, "auth_failed", &format!("Verification failed: {}", e))
        })?;

    let body = format!("success=true&nonce={}", nonce);

    Ok(success_response(body))
}