use std::sync::Arc;
use std::time::Duration;

use log::{info, warn};
use sea_orm::DatabaseConnection;

use crate::config::Config;
use crate::db;

/// Background task that refreshes Discord OAuth2 tokens before they expire.
/// Runs every 60 seconds. Refreshes tokens that are within 1/7 of their lifetime
/// from expiration (i.e., at the 6/7 mark).
pub async fn run(db: DatabaseConnection, config: Config) {
    info!("token refresh task started");

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;

        // Get all users needing refresh: token expires within 1 day
        // For a 7-day token, this means we refresh when 1 day remains.
        // That's roughly 6/7 of the lifetime.
        let margin_secs = 24 * 3600; // 1 day margin
        let users = match db::get_users_needing_refresh(&db, margin_secs).await {
            Ok(users) => users,
            Err(e) => {
                warn!("token_refresh: failed to query users: {}", e);
                continue;
            }
        };

        if users.is_empty() {
            continue;
        }

        info!("token_refresh: refreshing tokens for {} users", users.len());

        // Process each user (up to 10 concurrent to avoid rate limiting)
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let mut handles = Vec::new();

        for user in users {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let db_clone = db.clone();
            let config_ref = config.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                refresh_user_token(&db_clone, &user, &config_ref).await;
            }));
        }

        // Wait for all refreshes to complete
        for handle in handles {
            let _ = handle.await;
        }
    }
}

/// Refresh a single user's Discord OAuth2 token.
async fn refresh_user_token(db: &DatabaseConnection, user: &crate::models::Model, config: &Config) {
    let client = reqwest::Client::new();

    let params = [
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret),
        ("grant_type", &"refresh_token".to_string()),
        ("refresh_token", &user.refresh_token),
    ];

    let resp = client
        .post("https://discord.com/api/v10/oauth2/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            #[derive(serde::Deserialize)]
            struct RefreshResponse {
                access_token: String,
                refresh_token: Option<String>,
                expires_in: u64,
            }

            match r.json::<RefreshResponse>().await {
                Ok(token_resp) => {
                    let now = crate::crypto::now_secs();
                    let expires_at = now + token_resp.expires_in as i64;
                    let new_refresh = token_resp.refresh_token.unwrap_or(user.refresh_token.clone());

                    let uuid = match uuid::Uuid::parse_str(&user.uuid) {
                        Ok(u) => u,
                        Err(_) => {
                            warn!("token_refresh: invalid UUID in DB: {}", user.uuid);
                            return;
                        }
                    };

                    if let Err(e) = db::update_user_tokens(
                        db,
                        &uuid,
                        &token_resp.access_token,
                        &new_refresh,
                        expires_at,
                    ).await {
                        warn!("token_refresh: failed to update tokens for {}: {}", user.uuid, e);
                    } else {
                        info!("token_refresh: refreshed tokens for {}", user.uuid);
                    }
                }
                Err(e) => {
                    warn!("token_refresh: failed to parse refresh response for {}: {}", user.uuid, e);
                }
            }
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            warn!("token_refresh: Discord returned {} for {}: {}", status, user.uuid, body);
        }
        Err(e) => {
            warn!("token_refresh: network error for {}: {}", user.uuid, e);
        }
    }
}