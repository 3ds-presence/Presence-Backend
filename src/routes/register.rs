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
use discord_social_rpc::{CodeExchangeResponse, DiscordSocialRpcAdmin};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto;
use crate::db;
use crate::response::error_response;
use crate::response::success_response;
use crate::validation;
use crate::AppState;

#[derive(Deserialize)]
pub struct RegisterForm {
    pub code: String,
}

#[derive(serde::Deserialize)]
struct DiscordUserResponse {
    id: String,
}

/// POST /register — Exchange a Discord `OAuth2` code for an account.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RegisterForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let code = validation::validate_code(&form.code)?.to_owned();
    let discord_rpc = state.discord_rpc.clone();
    let debug = state.config.debug_mode;

    let token = exchange_discord_code(code, &state.config.redirect_uri, discord_rpc, debug).await?;
    let discord_id = fetch_discord_user_id(&token.access_token).await?;
    let now = crypto::now_secs();
    let expires_at = now + i64::try_from(token.expires_in).unwrap();

    if let Some(existing_user) = lookup_existing_user(&state.db, &discord_id).await? {
        return handle_returning_user(&state.db, existing_user, &token, expires_at).await;
    }

    handle_new_user(&state.db, &discord_id, &token, expires_at, now).await
}

/// Step 1: Exchange the `OAuth2` code for tokens via Discord.
async fn exchange_discord_code(
    code: String,
    redirect_uri: &str,
    discord_rpc: DiscordSocialRpcAdmin,
    debug: bool,
) -> Result<CodeExchangeResponse, axum::response::Response> {
    let redirect_uri = redirect_uri.to_owned();
    let token_resp =
        tokio::task::spawn_blocking(move || discord_rpc.exchange_code(&code, &redirect_uri))
            .await
            .map_err(|e| {
                let msg = if debug {
                    format!("Spawn blocking failed: {e}")
                } else {
                    "Internal error".to_string()
                };
                error_response(500, "runtime_error", &msg)
            })?
            .map_err(|e| {
                let msg = if debug {
                    format!("Discord error: {e}")
                } else {
                    "Discord authentication failed".to_string()
                };
                error_response(502, "discord_error", &msg)
            })?;

    Ok(token_resp)
}

/// Step 2: Fetch the Discord user ID (snowflake) from the access token.
async fn fetch_discord_user_id(access_token: &str) -> Result<String, axum::response::Response> {
    let client = reqwest::Client::new();
    let user_resp = client
        .get("https://discord.com/api/v10/users/@me")
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|_e| error_response(502, "discord_error", "Failed to fetch Discord user"))?;

    if !user_resp.status().is_success() {
        return Err(error_response(
            502,
            "discord_error",
            "Discord user endpoint failed",
        ));
    }

    let user_info: DiscordUserResponse = user_resp
        .json()
        .await
        .map_err(|_e| error_response(502, "discord_error", "Failed to parse Discord user"))?;

    Ok(user_info.id)
}

/// Step 3: Check if the Discord user already has an account.
async fn lookup_existing_user(
    db: &sea_orm::DatabaseConnection,
    discord_id: &str,
) -> Result<Option<crate::models::Model>, axum::response::Response> {
    db::get_user_by_discord_id(db, discord_id)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database query failed"))
}

/// Step 4a: Returning user — update tokens, preserve UUID and AES key.
async fn handle_returning_user(
    db: &sea_orm::DatabaseConnection,
    existing_user: crate::models::Model,
    token: &CodeExchangeResponse,
    expires_at: i64,
) -> Result<axum::response::Response, axum::response::Response> {
    let uuid = existing_user
        .uuid
        .parse::<Uuid>()
        .map_err(|_e| error_response(500, "db_error", "Invalid stored UUID"))?;

    db::update_user_tokens(
        db,
        &uuid,
        &token.access_token,
        &token.refresh_token,
        expires_at,
    )
    .await
    .map_err(|_e| error_response(500, "db_error", "Failed to update user tokens"))?;

    let aes_hex = hex::encode(&existing_user.aes_key);
    let body = format!("uuid={uuid}&aes_key_hex={aes_hex}");
    Ok(success_response(body))
}

/// Step 4b: New user — generate fresh UUID and AES key, create account.
async fn handle_new_user(
    db: &sea_orm::DatabaseConnection,
    discord_id: &str,
    token: &CodeExchangeResponse,
    expires_at: i64,
    now: i64,
) -> Result<axum::response::Response, axum::response::Response> {
    let uuid = Uuid::new_v4();
    let aes_key = crypto::generate_aes_key();

    db::create_user(db::CreateUserParams {
        db,
        uuid: &uuid,
        discord_id,
        aes_key: &aes_key,
        access_token: &token.access_token,
        refresh_token: &token.refresh_token,
        token_expires_at: expires_at,
        created_at: now,
    })
    .await
    .map_err(|_e| error_response(500, "db_error", "Failed to create user"))?;

    let aes_hex = hex::encode(aes_key);
    let body = format!("uuid={uuid}&aes_key_hex={aes_hex}");
    Ok(success_response(body))
}
