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
use std::time::Duration;

use discord_social_rpc::DiscordSocialRpcAdmin;
use log::{info, warn};
use sea_orm::DatabaseConnection;

use crate::crypto;
use crate::db;
use crate::models;

/// Refresh Discord `OAuth2` tokens before they expire (runs every hour).
pub async fn run_with_master_key(
    db: DatabaseConnection,
    admin: DiscordSocialRpcAdmin,
    master_key: &[u8; crypto::MASTER_KEY_LEN],
) {
    info!("token refresh task started");

    loop {
        tokio::time::sleep(Duration::from_hours(1)).await;

        let margin_secs = 24 * 3600; // refresh when ≤1 day remains
        let users = match db::get_users_needing_refresh(&db, margin_secs).await {
            Ok(users) => users,
            Err(e) => {
                warn!("token_refresh: failed to query users: {e}");
                continue;
            }
        };

        if users.is_empty() {
            continue;
        }

        info!("token_refresh: refreshing tokens for {} users", users.len());

        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let mut handles = Vec::new();

        for user in users {
            let db_clone = db.clone();
            let admin_clone = admin.clone();
            let sem_clone = semaphore.clone();

            let handle = spawn_user_refresh(sem_clone, db_clone, user, admin_clone, master_key);
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }
    }
}

/// Spawn a user refresh task with semaphore acquisition.
fn spawn_user_refresh(
    sem_clone: Arc<tokio::sync::Semaphore>,
    db_clone: DatabaseConnection,
    user: models::Model,
    admin_clone: DiscordSocialRpcAdmin,
    master_key: &[u8; crypto::MASTER_KEY_LEN],
) -> tokio::task::JoinHandle<()> {
    let master_key = *master_key;
    tokio::spawn(async move {
        let _permit = sem_clone.acquire_owned().await.unwrap();
        refresh_user_token(&db_clone, &user, &admin_clone, &master_key).await;
    })
}

/// Refresh a single user's token (RPC call is sync, so wrap in `spawn_blocking`).
async fn refresh_user_token(
    db: &DatabaseConnection,
    user: &models::Model,
    admin: &DiscordSocialRpcAdmin,
    master_key: &[u8; crypto::MASTER_KEY_LEN],
) {
    let admin = admin.clone();
    let refresh_token =
        crypto::decrypt_string_at_rest(&user.refresh_token, master_key).unwrap_or_default();
    let result =
        tokio::task::spawn_blocking(move || admin.refresh_user_token(&refresh_token)).await;

    match result {
        Ok(Ok(resp)) => apply_refresh(db, user, &resp, master_key).await,
        Ok(Err(e)) => handle_refresh_error(db, user, e).await,
        Err(e) => warn!("token_refresh: error for {}: {}", user.uuid, e),
    }
}

/// Handle a refresh failure.
///
/// Discord returns `invalid_grant` when the refresh token has been revoked
/// (or is invalid/expired). Such a token can never be refreshed again, so the
/// account is deleted rather than retried every hour forever.
async fn handle_refresh_error(
    db: &DatabaseConnection,
    user: &models::Model,
    e: discord_social_rpc::Error,
) {
    let msg = e.to_string();
    if is_invalid_grant(&msg) {
        warn!(
            "token_refresh: refresh token invalid/revoked for {}, deleting account",
            user.uuid
        );
        let Ok(uuid) = uuid::Uuid::parse_str(&user.uuid) else {
            warn!("token_refresh: invalid UUID in DB: {}", user.uuid);
            return;
        };
        match db::delete_user(db, &uuid).await {
            Ok(()) => info!("token_refresh: deleted user {} (token revoked)", user.uuid),
            Err(e) => warn!(
                "token_refresh: failed to delete revoked user {}: {}",
                user.uuid, e
            ),
        }
    } else {
        warn!("token_refresh: error for {}: {}", user.uuid, msg);
    }
}

/// Discord returns `invalid_grant` (HTTP 400) when a refresh token is revoked
/// or has already been used.
fn is_invalid_grant(error_msg: &str) -> bool {
    error_msg.contains("invalid_grant")
}

async fn apply_refresh(
    db: &DatabaseConnection,
    user: &models::Model,
    resp: &discord_social_rpc::TokenRefreshResponse,
    master_key: &[u8; crypto::MASTER_KEY_LEN],
) {
    let now = crypto::now_secs();
    let expires_at = now + i64::try_from(resp.expires_in).unwrap();
    let new_refresh = resp
        .refresh_token
        .clone()
        .unwrap_or_else(|| user.refresh_token.clone());

    let Ok(uuid) = uuid::Uuid::parse_str(&user.uuid) else {
        warn!("token_refresh: invalid UUID in DB: {}", user.uuid);
        return;
    };

    if let Err(e) = db::update_user_tokens(
        db,
        master_key,
        &uuid,
        &resp.access_token,
        &new_refresh,
        expires_at,
    )
    .await
    {
        warn!(
            "token_refresh: failed to update tokens for {}: {}",
            user.uuid, e
        );
    } else {
        info!("token_refresh: refreshed tokens for {}", user.uuid);
    }
}
