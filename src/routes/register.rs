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

use axum::{extract::State, Form};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto;
use crate::db;
use crate::response::error_response;
use crate::response::success_response;
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

    // Exchange the code with Discord for tokens via DiscordSocialRpcAdmin.
    let code = form.code.clone();
    let redirect_uri = state.config.redirect_uri.clone();
    let discord_rpc = state.discord_rpc.clone();
    
    let debug = state.config.debug_mode;
    let token_resp =
        tokio::task::spawn_blocking(move || discord_rpc.exchange_code(&code, &redirect_uri))
            .await
            .map_err(|e| {
                let msg = if debug { format!("Spawn blocking failed: {}", e) } else { "Internal error".to_string() };
                error_response(500, "runtime_error", &msg)
            })?
            .map_err(|e| {
                let msg = if debug { format!("Discord error: {}", e) } else { "Discord authentication failed".to_string() };
                error_response(502, "discord_error", &msg)
            })?;

    // Fetch the Discord user's identity (to get their snowflake ID)
    let client = reqwest::Client::new();
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

        return Ok(success_response(body));
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

    Ok(success_response(body))
}