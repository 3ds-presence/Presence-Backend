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

use crate::db;

/// Refresh Discord `OAuth2` tokens before they expire (runs every hour).
pub async fn run(db: DatabaseConnection, admin: DiscordSocialRpcAdmin) {
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

            let handle = spawn_user_refresh(sem_clone, db_clone, user, admin_clone);
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
    db_clone: sea_orm::DatabaseConnection,
    user: crate::models::Model,
    admin_clone: DiscordSocialRpcAdmin,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _permit = sem_clone.acquire_owned().await.unwrap();
        refresh_user_token(&db_clone, &user, &admin_clone).await;
    })
}

/// Refresh a single user's token (RPC call is sync, so wrap in `spawn_blocking`).
async fn refresh_user_token(
    db: &DatabaseConnection,
    user: &crate::models::Model,
    admin: &DiscordSocialRpcAdmin,
) {
    let admin = admin.clone();
    let refresh_token = user.refresh_token.clone();
    let result =
        tokio::task::spawn_blocking(move || admin.refresh_user_token(&refresh_token)).await;

    match result {
        Ok(Ok(resp)) => apply_refresh(db, user, &resp).await,
        Ok(Err(e)) => warn!("token_refresh: error for {}: {}", user.uuid, e),
        Err(e) => warn!("token_refresh: error for {}: {}", user.uuid, e),
    }
}

async fn apply_refresh(
    db: &DatabaseConnection,
    user: &crate::models::Model,
    resp: &discord_social_rpc::TokenRefreshResponse,
) {
    let now = crate::crypto::now_secs();
    let expires_at = now + i64::try_from(resp.expires_in).unwrap();
    let new_refresh = resp
        .refresh_token
        .clone()
        .unwrap_or_else(|| user.refresh_token.clone());

    let Ok(uuid) = uuid::Uuid::parse_str(&user.uuid) else {
        warn!("token_refresh: invalid UUID in DB: {}", user.uuid);
        return;
    };

    if let Err(e) =
        db::update_user_tokens(db, &uuid, &resp.access_token, &new_refresh, expires_at).await
    {
        warn!(
            "token_refresh: failed to update tokens for {}: {}",
            user.uuid, e
        );
    } else {
        info!("token_refresh: refreshed tokens for {}", user.uuid);
    }
}
