use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto;
use crate::db;
use crate::AppState;

#[derive(Deserialize)]
pub struct RegisterForm {
    pub code: String,
}

/// POST /register — Exchange a Discord OAuth2 code for an account.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RegisterForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    if form.code.is_empty() {
        return Err(error_response(400, "missing_code", "Code is required"));
    }

    // Exchange the code with Discord for tokens
    let client = reqwest::Client::new();
    let params = [
        ("client_id", state.config.client_id.as_str()),
        ("client_secret", state.config.client_secret.as_str()),
        ("grant_type", "authorization_code"),
        ("code", &form.code),
        ("redirect_uri", &state.config.redirect_uri),
    ];

    let discord_resp = client
        .post("https://discord.com/api/v10/oauth2/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|e| error_response(502, "discord_error", &format!("Discord request failed: {}", e)))?;

    if !discord_resp.status().is_success() {
        let status = discord_resp.status().as_u16();
        return Err(error_response(502, "discord_error", &format!("Discord returned HTTP {}", status)));
    }

    #[derive(serde::Deserialize)]
    struct DiscordTokenResponse {
        access_token: String,
        refresh_token: String,
        expires_in: u64,
    }

    let token_resp: DiscordTokenResponse = discord_resp.json().await
        .map_err(|_e| error_response(502, "discord_error", "Failed to parse Discord response"))?;

    // Generate UUID and AES key
    let uuid = Uuid::new_v4();
    let aes_key = crypto::generate_aes_key();
    let now = crypto::now_secs();
    let expires_at = now + token_resp.expires_in as i64;

    // Save to database
    db::create_user(
        &state.db,
        &uuid,
        &aes_key,
        &token_resp.access_token,
        &token_resp.refresh_token,
        expires_at,
        now,
    )
    .await
    .map_err(|_e| error_response(500, "db_error", "Failed to create user"))?;

    let aes_hex = hex::encode(aes_key);
    let body = format!("uuid={}&aes_key_hex={}", uuid, aes_hex);

    Ok(axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap())
}

/// Build an error response with form-urlencoded body.
pub fn error_response(status: u16, code: &str, message: &str) -> axum::response::Response {
    let encoded = message.replace(' ', "+");
    let body = format!("error={}&message={}", code, encoded);
    axum::response::Response::builder()
        .status(status)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap()
}