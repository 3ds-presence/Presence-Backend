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

use super::{SessionError, SessionManager, SessionState};
use crate::auth::Auth;
use crate::crypto::{self, url_encode_3ds};
use crate::AppState;
use activity_generator::UserInfo;

impl SessionManager {
    /// Run `f` with the active session for `auth.uuid` locked.
    ///
    /// The lock is held for the whole closure, so callers can verify and
    /// commit the counter atomically (replay protection). Returns
    /// `SessionNotFound` when the session is missing or not active.
    async fn with_active_session<T>(
        &self,
        auth: &Auth,
        f: impl FnOnce(&mut SessionState) -> Result<T, SessionError>,
    ) -> Result<T, SessionError> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(&auth.uuid)
            .ok_or(SessionError::SessionNotFound)?;
        let res = f(session);
        drop(sessions);
        res
    }

    async fn authenticate_and_get_client(
        &self,
        auth: &Auth,
        fields: &[&str],
        cooldown_secs: u64,
    ) -> Result<(Arc<DiscordRpcClient>, IpAddr, u64), SessionError> {
        self.with_active_session(auth, |session| {
            let SessionState::Active {
                client,
                aes_key,
                last_counter,
                last_activity,
                client_ip,
                ..
            } = session
            else {
                return Err(SessionError::SessionNotFound);
            };
            check_cooldown(*last_activity, cooldown_secs)?;
            let good_counter = last_counter.load(Ordering::SeqCst) + 1;
            crypto::verify_activity_auth(auth.hex(), good_counter, fields, aes_key)
                .map_err(|e| SessionError::AuthFailed(e.to_string()))?;
            Ok((client.clone(), *client_ip, good_counter))
        })
        .await
    }

    pub async fn authenticate_and_tick(
        &self,
        auth: &Auth,
        fields: &[&str],
        cooldown_secs: u64,
    ) -> Result<(Arc<DiscordRpcClient>, u64), SessionError> {
        self.with_active_session(auth, |session| {
            // Counter check + increment under one lock, or concurrent requests bypass replay protection.
            let SessionState::Active {
                client,
                aes_key,
                last_counter,
                last_activity,
                ..
            } = session
            else {
                return Err(SessionError::SessionNotFound);
            };
            check_cooldown(*last_activity, cooldown_secs)?;
            let good_counter = last_counter.load(Ordering::SeqCst) + 1;
            crypto::verify_activity_auth(auth.hex(), good_counter, fields, aes_key)
                .map_err(|e| SessionError::AuthFailed(e.to_string()))?;

            // Update the counter and activity timestamp under the same lock.
            last_counter.store(good_counter, Ordering::SeqCst);
            *last_activity = Instant::now();
            Ok((client.clone(), good_counter))
        })
        .await
    }

    /// Verify an authenticated request and consume one counter tick, without
    /// applying the activity cooldown or touching `last_activity`.
    ///
    /// Used by routes that authenticate client requests but should not affect
    /// activity pacing. Returns the verified counter so callers can sign a
    /// response for the same tick.
    pub async fn verify_and_tick(&self, auth: &Auth, fields: &[&str]) -> Result<u64, SessionError> {
        self.with_active_session(auth, |session| {
            // Counter check + increment under one lock, or concurrent requests bypass replay protection.
            let SessionState::Active {
                aes_key,
                last_counter,
                ..
            } = session
            else {
                return Err(SessionError::SessionNotFound);
            };
            let good_counter = last_counter.load(Ordering::SeqCst) + 1;
            crypto::verify_activity_auth(auth.hex(), good_counter, fields, aes_key)
                .map_err(|e| SessionError::AuthFailed(e.to_string()))?;

            // Update the counter under the same lock.
            last_counter.store(good_counter, Ordering::SeqCst);
            Ok(good_counter)
        })
        .await
    }

    /// Sign a response payload for the active session of `auth.uuid` using the
    /// account AES key, binding `counter` and `fields` in the same envelope as
    /// the client-side `build_auth`.
    ///
    /// The 3DS decrypts the returned hex with its AES key and checks that the
    /// counter and the SHA-256 of the fields match, proving the response came
    /// from the server and was not tampered with or replayed.
    pub async fn sign_response(
        &self,
        auth: &Auth,
        counter: u64,
        fields: &[&str],
    ) -> Result<String, SessionError> {
        let sessions = self.sessions.lock().await;
        let session = sessions
            .get(&auth.uuid)
            .ok_or(SessionError::SessionNotFound)?;
        let SessionState::Active { aes_key, .. } = session else {
            return Err(SessionError::SessionNotFound);
        };
        let res = Ok(crypto::encrypt_auth(counter, fields, aes_key));
        drop(sessions);
        res
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
