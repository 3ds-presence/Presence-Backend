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

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use activity_generator::info::GameInfo;
use discord_social_rpc::{Activity, ActivityStatus, DiscordRpcClient};
use uuid::Uuid;

use activity_generator::UserInfo;
use crate::auth::Auth;
use crate::crypto::{self, url_encode_3ds};
use crate::AppState;
use super::{SessionError, SessionManager, SessionState};

impl SessionManager {
    async fn authenticate_and_get_client(
        &self,
        auth: &Auth,
        fields: &[&str],
        cooldown_secs: u64,
    ) -> Result<(Arc<DiscordRpcClient>, IpAddr, u64), SessionError> {
        let (client, aes_key, last_counter, last_activity, client_ip) =
            self.lock_and_fetch_active(auth).await?;
        check_cooldown(last_activity, cooldown_secs)?;
        let good_counter = last_counter + 1;
        crypto::verify_activity_auth(auth.hex(), good_counter, fields, &aes_key)
            .map_err(|e| SessionError::AuthFailed(e.to_string()))?;
        Ok((client, client_ip, good_counter))
    }

    async fn lock_and_fetch_active(
        &self,
        auth: &Auth,
    ) -> Result<(Arc<DiscordRpcClient>, [u8; 32], u64, Instant, IpAddr), SessionError> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(&auth.uuid)
            .ok_or(SessionError::SessionNotFound)?;
        let result = match session {
            SessionState::Active {
                client,
                aes_key,
                last_counter,
                last_activity,
                client_ip,
                ..
            } => Ok((
                client.clone(),
                *aes_key,
                last_counter.load(Ordering::SeqCst),
                *last_activity,
                *client_ip,
            )),
            SessionState::PendingVerify { .. } => Err(SessionError::PendingNotActive),
            SessionState::PendingConsent { .. } => {
                Err(SessionError::from("session is pending consent, not active"))
            }
        };
        drop(sessions);
        result
    }

    pub async fn authenticate_and_tick(
        &self,
        auth: &Auth,
        fields: &[&str],
        cooldown_secs: u64,
    ) -> Result<(Arc<DiscordRpcClient>, u64), SessionError> {
        // Counter check + increment under one lock, or concurrent requests bypass replay protection.
        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(&auth.uuid)
            .ok_or(SessionError::SessionNotFound)?;
        let (client, aes_key, last_counter, last_activity) = match session {
            SessionState::Active {
                client,
                aes_key,
                last_counter,
                last_activity,
                ..
            } => (
                client.clone(),
                *aes_key,
                last_counter.load(Ordering::SeqCst),
                *last_activity,
            ),
            SessionState::PendingVerify { .. } => return Err(SessionError::PendingNotActive),
            SessionState::PendingConsent { .. } => {
                return Err(SessionError::from("session is pending consent, not active"))
            }
        };

        check_cooldown(last_activity, cooldown_secs)?;
        let good_counter = last_counter + 1;
        crypto::verify_activity_auth(auth.hex(), good_counter, fields, &aes_key)
            .map_err(|e| SessionError::AuthFailed(e.to_string()))?;

        // Update the counter and activity timestamp under the same lock.
        if let SessionState::Active {
            last_counter,
            last_activity,
            ..
        } = session
        {
            last_counter.store(good_counter, Ordering::SeqCst);
            *last_activity = Instant::now();
        }
        drop(sessions);
        Ok((client, good_counter))
    }

    pub async fn update_activity(
        &self,
        state: &AppState,
        auth: &Auth,
        game_info: Option<GameInfo>,
        extra_info: Option<String>,
    ) -> Result<(), SessionError> {
        let field = Self::build_field_string(game_info.as_ref(), extra_info.as_deref());
        let fields = [field.as_str()];
        let (client, _good_counter) = self
            .authenticate_and_tick(auth, &fields, state.config.activity_cooldown_secs)
            .await?;
        if let Err(e) = ensure_client_alive(&client) {
            self.remove_dead_session(&auth.uuid).await;
            return Err(e);
        }
        let user_info = self.fetch_user_info(auth).await;

        let activity = if let Some(game_info) = &game_info {
            state
                .activity_generator
                .build_activity(&user_info.unwrap_or_default(), game_info, &extra_info)
                .await
        } else {
            Activity::default()
        };
        self.spawn_set_activity(client, activity).await
    }

    fn build_field_string(game_info: Option<&GameInfo>, extra_info: Option<&str>) -> String {
        let base = game_info.map_or_else(String::new, |info| {
            format!(
                "titleid={}&name={}&publisher={}",
                url_encode_3ds(&info.title_id),
                url_encode_3ds(&info.name),
                url_encode_3ds(&info.publisher)
            )
        });
        match extra_info {
            Some(extra) => format!("{}&extra={}", base, url_encode_3ds(extra)),
            None => base,
        }
    }

    async fn fetch_user_info(&self, auth: &Auth) -> Option<UserInfo> {
        let sessions = self.sessions.lock().await;
        match sessions.get(&auth.uuid) {
            Some(SessionState::Active { user_info, .. }) => user_info.clone(),
            _ => None,
        }
    }

    async fn spawn_set_activity(
        &self,
        client: Arc<DiscordRpcClient>,
        activity: discord_social_rpc::Activity,
    ) -> Result<(), SessionError> {
        tokio::task::spawn_blocking(move || client.set_activity(&activity))
            .await
            .map_err(|e| SessionError::from(format!("set_activity spawn failed: {e}")))?
            .map_err(|e| match e {
                discord_social_rpc::Error::InvalidToken(_) => SessionError::TokenRevoked,
                other => SessionError::from(format!("set_activity failed: {other}")),
            })?;
        Ok(())
    }

    pub async fn heartbeat(&self, auth: &Auth, cooldown_secs: u64) -> Result<(), SessionError> {
        let fields: [&str; 0] = [];
        let (client, _good_counter) = self
            .authenticate_and_tick(auth, &fields, cooldown_secs)
            .await?;
        if let Err(e) = ensure_client_alive(&client) {
            self.remove_dead_session(&auth.uuid).await;
            return Err(e);
        }
        Ok(())
    }

    pub async fn stop_activity(&self, auth: &Auth, cooldown_secs: u64) -> Result<(), SessionError> {
        let fields = ["logout", "", ""];
        let (client, _client_ip, _good_counter) = self
            .authenticate_and_get_client(auth, &fields, cooldown_secs)
            .await?;
        stop_discord_client(client).await;
        self.remove_session(&auth.uuid).await;
        log::info!("session {}: activity stopped by client (logout)", auth.uuid);
        Ok(())
    }

    /// Stop and remove a session without auth — used by background tasks
    /// (timeout/cleanup) that already hold a UUID.
    pub async fn terminate_session(&self, uuid: &Uuid) {
        let state = self.remove_session(uuid).await;
        if let Some(SessionState::Active { client, .. }) = state {
            stop_discord_client(client).await;
        }
        log::info!("session {uuid}: terminated");
    }
}

/// Check that the Discord gateway connection is still usable.
///
/// `Disconnected` is expected during reconnect backoff and is therefore
/// allowed. `TokenInvalid` means the user revoked the token in Discord.
/// `Stopped`/`NetworkError` while the session is still registered means the
/// gateway died unexpectedly (the session is only removed after a normal
/// `stop_activity`, so reaching this check implies an abnormal exit).
fn ensure_client_alive(client: &DiscordRpcClient) -> Result<(), SessionError> {
    match client.activity_status() {
        ActivityStatus::Ok | ActivityStatus::Disconnected | ActivityStatus::NotStarted => Ok(()),
        ActivityStatus::TokenInvalid => Err(SessionError::TokenRevoked),
        ActivityStatus::NetworkError | ActivityStatus::Stopped => {
            Err(SessionError::SessionNotFound)
        }
    }
}

fn check_cooldown(last_activity: Instant, cooldown_secs: u64) -> Result<(), SessionError> {
    let elapsed = last_activity.elapsed().as_secs();
    if elapsed < cooldown_secs {
        return Err(SessionError::Cooldown {
            remaining: cooldown_secs - elapsed,
        });
    }
    Ok(())
}

async fn stop_discord_client(client: Arc<DiscordRpcClient>) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = client.stop_activity();
    })
    .await;
}