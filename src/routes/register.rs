use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto;
use crate::db;
use crate::error::error_response;
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

    // Fetch the Discord user's identity (to get their snowflake ID)
    let user_resp = client
        .get("https://discord.com/api/v10/users/@me")
        .header("Authorization", format!("Bearer {}", token_resp.access_token))
        .send()
        .await
        .map_err(|_e| error_response(502, "discord_error", "Failed to fetch Discord user"))?;

    if !user_resp.status().is_success() {
        return Err(error_response(502, "discord_error", "Discord user endpoint failed"));
    }

    #[derive(serde::Deserialize)]
    struct DiscordUserResponse {
        id: String,
    }

    let user_info: DiscordUserResponse = user_resp.json().await
        .map_err(|_e| error_response(502, "discord_error", "Failed to parse Discord user"))?;

    let discord_id = &user_info.id;
    let now = crypto::now_secs();
    let expires_at = now + token_resp.expires_in as i64;

    // Check if this Discord user has already registered
    if let Some(existing_user) = db::get_user_by_discord_id(&state.db, discord_id)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database query failed"))?
    {
        // Returning user: preserve uuid and aes_key, update tokens only
        let uuid = existing_user.uuid.parse::<Uuid>()
            .map_err(|_e| error_response(500, "db_error", "Invalid stored UUID"))?;

        db::update_user_tokens(
            &state.db,
            &uuid,
            &token_resp.access_token,
            &token_resp.refresh_token,
            expires_at,
        )
        .await
        .map_err(|_e| error_response(500, "db_error", "Failed to update user tokens"))?;

        let aes_hex = hex::encode(&existing_user.aes_key);
        let body = format!("uuid={}&aes_key_hex={}", uuid, aes_hex);

        return Ok(axum::response::Response::builder()
            .status(200)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.into())
            .unwrap());
    }

    // New user: generate a fresh UUID and AES key
    let uuid = Uuid::new_v4();
    let aes_key = crypto::generate_aes_key();

    db::create_user(
        &state.db,
        &uuid,
        discord_id,
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
