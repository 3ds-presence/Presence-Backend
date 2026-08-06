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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use activity_generator::info::GameInfo;
use axum::response::{IntoResponse, Response};
use discord_social_rpc::{Activity, ActivityStatus, DiscordRpcClient, DiscordSocialRpc};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::crypto::url_encode_3ds;
use crate::response::error_response;
use crate::{auth::Auth, crypto, AppState};
use activity_generator::UserInfo;

/// Timeout for pending verification sessions (seconds).
const PENDING_TIMEOUT_SECS: u64 = 30;
/// Timeout for pending consent sessions (seconds).
const PENDING_CONSENT_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// State of a session during the login flow.
pub enum SessionState {
    /// Waiting for the client to prove they have the AES key.
    PendingVerify {
        nonce: u64,
        aes_key: [u8; 32],
        created_at: Instant,
        client_ip: IpAddr,
    },
    /// Waiting for the user to accept the privacy policy (RGPD consent).
    PendingConsent {
        discord_id: String,
        access_token: String,
        refresh_token: String,
        token_expires_at: i64,
        temp_token: Uuid,
        created_at: Instant,
    },
    /// Session is active — `DiscordRpcClient` is connected and running.
    Active {
        client: Arc<DiscordRpcClient>,
        aes_key: [u8; 32],
        last_counter: AtomicU64,
        last_activity: Instant,
        client_ip: IpAddr,
        user_info: Option<UserInfo>,
    },
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingVerify { nonce, .. } => f
                .debug_struct("PendingVerify")
                .field("nonce", nonce)
                .finish(),
            Self::PendingConsent {
                temp_token,
                created_at,
                ..
            } => f
                .debug_struct("PendingConsent")
                .field("temp_token", temp_token)
                .field("created_at", created_at)
                .finish(),
            Self::Active {
                last_activity,
                user_info,
                ..
            } => f
                .debug_struct("Active")
                .field("last_activity", last_activity)
                .field("user_info", user_info)
                .finish(),
        }
    }
}

/// Custom session error type.
#[derive(Debug)]
pub enum SessionError {
    SessionNotFound,
    PendingNotActive,
    AuthFailed(String),
    ReplayDetected {
        counter: u64,
        last: u64,
    },
    Cooldown {
        remaining: u64,
    },
    /// The Discord `OAuth2` token was revoked or rejected by Discord.
    TokenRevoked,
    Other(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "session not found"),
            Self::PendingNotActive => write!(f, "session is pending verification, not active"),
            Self::AuthFailed(msg) => write!(f, "auth verification failed: {msg}"),
            Self::ReplayDetected { counter, last } => {
                write!(f, "replay detected: counter {counter} <= last {last}")
            }
            Self::Cooldown { remaining } => write!(f, "cooldown: wait {remaining} seconds"),
            Self::TokenRevoked => write!(f, "Discord OAuth2 token revoked"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        make_session_error_response(&self)
    }
}

impl From<&str> for SessionError {
    fn from(s: &str) -> Self {
        Self::Other(s.to_string())
    }
}

impl From<String> for SessionError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

/// Parameters for promoting a pending session to active.
pub struct PromoteToActiveParams<'a> {
    pub auth: &'a Auth,
    pub client: Arc<DiscordRpcClient>,
    pub aes_key: [u8; 32],
    pub nonce: u64,
    pub cooldown_secs: u64,
    pub client_ip: IpAddr,
    pub user_info: Option<UserInfo>,
}

/// Manages all active and pending sessions, with IP-based rate limiting.
pub struct SessionManager {
    sessions: Mutex<HashMap<Uuid, SessionState>>,
    ip_counts: Mutex<HashMap<IpAddr, usize>>,
    /// Pending consent sessions indexed by `temp_token`.
    consent_sessions: Mutex<HashMap<Uuid, Uuid>>, // temp_token -> session uuid
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ip_counts: Mutex::new(HashMap::new()),
            consent_sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Decrement the IP counter for a given address.
    fn decrement_ip(ip_counts: &mut HashMap<IpAddr, usize>, ip: IpAddr) {
        match ip_counts.get_mut(&ip) {
            Some(count) if *count > 1 => *count -= 1,
            _ => {
                ip_counts.remove(&ip);
            }
        }
    }

    /// Remove a session by UUID, decrement IP counter, and return its state.
    pub async fn remove_session(&self, uuid: &Uuid) -> Option<SessionState> {
        let state = self.sessions.lock().await.remove(uuid);
        if let Some(ref s) = state {
            self.remove_consent_mapping(s).await;
            let mut ip_counts = self.ip_counts.lock().await;
            let ip = s.client_ip();
            Self::decrement_ip(&mut ip_counts, ip);
        }
        state
    }

    /// If the state is `PendingConsent`, remove the `temp_token` -> uuid mapping.
    async fn remove_consent_mapping(&self, state: &SessionState) {
        if let SessionState::PendingConsent { temp_token, .. } = state {
            self.consent_sessions.lock().await.remove(temp_token);
        }
    }

    /// Create a new pending consent session (after Discord OAuth, before user accepts RGPD).
    pub async fn create_pending_consent(
        &self,
        discord_id: String,
        access_token: String,
        refresh_token: String,
        token_expires_at: i64,
    ) -> Uuid {
        let temp_token = Uuid::new_v4();
        let uuid = Uuid::new_v4();
        self.sessions.lock().await.insert(
            uuid,
            SessionState::PendingConsent {
                discord_id,
                access_token,
                refresh_token,
                token_expires_at,
                temp_token,
                created_at: Instant::now(),
            },
        );
        self.consent_sessions.lock().await.insert(temp_token, uuid);
        log::info!("pending consent session created: temp_token={temp_token}");
        temp_token
    }

    /// Confirm consent and return stored Discord data. Removes the pending session.
    pub async fn confirm_consent(
        &self,
        temp_token: &Uuid,
    ) -> Result<(String, String, String, i64), &'static str> {
        let uuid = self
            .consent_sessions
            .lock()
            .await
            .remove(temp_token)
            .ok_or("consent session not found or expired")?;
        let state = self
            .sessions
            .lock()
            .await
            .remove(&uuid)
            .ok_or("consent session not found")?;
        match state {
            SessionState::PendingConsent {
                discord_id,
                access_token,
                refresh_token,
                token_expires_at,
                ..
            } => Ok((discord_id, access_token, refresh_token, token_expires_at)),
            _ => Err("unexpected session state"),
        }
    }

    /// Create a new pending session with a nonce challenge.
    pub async fn create_pending(
        &self,
        uuid: Uuid,
        aes_key: [u8; 32],
        client_ip: IpAddr,
        max_per_ip: usize,
    ) -> Result<u64, &'static str> {
        let nonce = crypto::generate_nonce();
        let mut ip_counts = self.ip_counts.lock().await;
        let count = ip_counts.entry(client_ip).or_insert(0);
        if *count >= max_per_ip {
            return Err("too many sessions from this IP");
        }
        *count += 1;
        drop(ip_counts);
        self.sessions.lock().await.insert(
            uuid,
            SessionState::PendingVerify {
                nonce,
                aes_key,
                created_at: Instant::now(),
                client_ip,
            },
        );
        Ok(nonce)
    }

    /// Verify a pending session: check the encrypted nonce and promote to active.
    pub async fn verify_and_activate(
        &self,
        auth: &Auth,
        discord_rpc: &DiscordSocialRpc,
        access_token: &str,
        cooldown_secs: u64,
        user_info: Option<UserInfo>,
    ) -> Result<u64, SessionError> {
        let (nonce, aes_key, client_ip) = self.extract_pending_state(auth).await?;
        verify_nonce(auth, &aes_key, nonce)?;
        let client = self
            .create_and_start_client(discord_rpc, access_token)
            .await?;
        self.promote_to_active(PromoteToActiveParams {
            auth,
            client,
            aes_key,
            nonce,
            cooldown_secs,
            client_ip,
            user_info,
        })
        .await;
        Ok(nonce)
    }

    async fn extract_pending_state(
        &self,
        auth: &Auth,
    ) -> Result<(u64, [u8; 32], IpAddr), SessionError> {
        let state = self
            .remove_session(&auth.uuid)
            .await
            .ok_or_else(|| SessionError::from("no pending session for this uuid"))?;
        match state {
            SessionState::PendingVerify {
                nonce,
                aes_key,
                client_ip,
                ..
            } => Ok((nonce, aes_key, client_ip)),
            SessionState::Active { .. } => Err("session is already active".into()),
            SessionState::PendingConsent { .. } => Err("session is pending consent".into()),
        }
    }

    async fn create_and_start_client(
        &self,
        discord_rpc: &DiscordSocialRpc,
        access_token: &str,
    ) -> Result<Arc<DiscordRpcClient>, SessionError> {
        let client = discord_rpc
            .create_new_client(access_token)
            .map_err(|e| SessionError::from(format!("failed to create Discord client: {e}")))?;
        let client = Arc::new(client);
        let client_clone = client.clone();
        // Propagate the gateway result: a revoked/rejected token must surface
        // to the client instead of being silently ignored.
        tokio::task::spawn_blocking(move || client_clone.start_activity())
            .await
            .map_err(|e| SessionError::from(format!("spawn_blocking failed: {e}")))?
            .map_err(|e| match e {
                discord_social_rpc::Error::InvalidToken(_) => SessionError::TokenRevoked,
                other => SessionError::from(format!("failed to start Discord client: {other}")),
            })?;
        Ok(client)
    }

    async fn promote_to_active(&self, params: PromoteToActiveParams<'_>) {
        let last_activity = Instant::now()
            .checked_sub(Duration::from_secs(params.cooldown_secs + 1))
            .unwrap();
        self.sessions.lock().await.insert(
            params.auth.uuid,
            SessionState::Active {
                client: params.client,
                aes_key: params.aes_key,
                last_counter: AtomicU64::new(params.nonce),
                last_activity,
                client_ip: params.client_ip,
                user_info: params.user_info,
            },
        );
        log::info!(
            "session {}: Discord client created and gateway started",
            params.auth.uuid
        );
    }

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

    pub async fn get_expired_active_sessions(&self, timeout_secs: u64) -> Vec<Uuid> {
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .filter_map(|(uuid, state)| Self::is_expired(state, timeout_secs).then_some(*uuid))
            .collect()
    }

    fn is_expired(state: &SessionState, timeout_secs: u64) -> bool {
        match state {
            SessionState::Active { last_activity, .. } => {
                last_activity.elapsed().as_secs() > timeout_secs
            }
            SessionState::PendingVerify { created_at, .. } => {
                created_at.elapsed().as_secs() > PENDING_TIMEOUT_SECS
            }
            SessionState::PendingConsent { created_at, .. } => {
                created_at.elapsed().as_secs() > PENDING_CONSENT_TIMEOUT_SECS
            }
        }
    }

    pub async fn is_active(&self, uuid: &Uuid) -> bool {
        let sessions = self.sessions.lock().await;
        matches!(sessions.get(uuid), Some(SessionState::Active { .. }))
    }

    pub async fn get_client(&self, uuid: &Uuid) -> Option<Arc<DiscordRpcClient>> {
        let sessions = self.sessions.lock().await;
        match sessions.get(uuid) {
            Some(SessionState::Active { client, .. }) => Some(client.clone()),
            _ => None,
        }
    }

    /// Remove a session whose Discord connection died (token revoked, gateway
    /// closed unexpectedly). Stops the client and decrements the IP counter.
    async fn remove_dead_session(&self, uuid: &Uuid) {
        let state = self.remove_session(uuid).await;
        if let Some(SessionState::Active { client, .. }) = state {
            let _ = tokio::task::spawn_blocking(move || client.stop_activity()).await;
        }
        log::info!("session {uuid}: removed (Discord connection died)");
    }
}

impl SessionState {
    pub const fn client_ip(&self) -> IpAddr {
        match self {
            Self::PendingVerify { client_ip, .. } | Self::Active { client_ip, .. } => *client_ip,
            Self::PendingConsent { .. } => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        }
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

fn verify_nonce(auth: &Auth, aes_key: &[u8; 32], expected_nonce: u64) -> Result<(), SessionError> {
    let cipher_bytes =
        hex::decode(auth.hex()).map_err(|_| SessionError::from("invalid hex in cipher_hex"))?;
    if cipher_bytes.len() != 16 {
        return Err("cipher_hex must be 32 hex chars (16 bytes)".into());
    }
    let mut cipher_arr = [0u8; 16];
    cipher_arr.copy_from_slice(&cipher_bytes);
    let plaintext = crypto::decrypt_aes_cbc(&cipher_arr, aes_key)
        .map_err(|e| SessionError::from(format!("decryption failed: {e}")))?;
    if plaintext.len() < 8 {
        return Err("decrypted data too short".into());
    }
    let extracted_nonce = crypto::u64_from_be_bytes(&plaintext[..8]);
    if extracted_nonce != expected_nonce {
        return Err("nonce mismatch".into());
    }
    Ok(())
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

/// Build a safe (default) session error response.
///
/// Message details that could be used as a security oracle (e.g. AES-CBC
/// padding / integrity errors, internal error strings) are never exposed
/// here. Routes that want verbose messages must call
/// [`session_error_into_response`] with `debug_mode` — and even then only
/// non-sensitive error kinds are detailed (see [`session_error_into_response`]).
fn make_session_error_response(err: &SessionError) -> Response {
    match err {
        SessionError::SessionNotFound | SessionError::PendingNotActive => error_response(
            401,
            "session_expired",
            "Session expired or not found. Please re-login.",
        ),
        SessionError::TokenRevoked => error_response(
            401,
            "token_revoked",
            "Discord OAuth2 token revoked. Please re-login.",
        ),
        // Never leak padding/integrity details (padding oracle).
        SessionError::AuthFailed(_) => error_response(403, "auth_failed", "Authentication failed"),
        SessionError::ReplayDetected { .. } => {
            error_response(403, "replay_detected", "Replay detected")
        }
        SessionError::Cooldown { remaining } => {
            error_response(429, "cooldown", &format!("Wait {remaining} seconds"))
        }
        SessionError::Other(_) => error_response(400, "error", "Request failed"),
    }
}

pub fn session_error_into_response(err: SessionError, debug_mode: bool) -> Response {
    match err {
        SessionError::SessionNotFound | SessionError::PendingNotActive => error_response(
            401,
            "session_expired",
            "Session expired or not found. Please re-login.",
        ),
        SessionError::TokenRevoked => error_response(
            401,
            "token_revoked",
            "Discord OAuth2 token revoked. Please re-login.",
        ),
        SessionError::AuthFailed(_) => {
            let msg = if debug_mode {
                err.to_string()
            } else {
                "Authentication failed".to_string()
            };
            error_response(403, "auth_failed", &msg)
        }
        SessionError::ReplayDetected { .. } => {
            let msg = if debug_mode {
                err.to_string()
            } else {
                "Replay detected".to_string()
            };
            error_response(403, "replay_detected", &msg)
        }
        SessionError::Cooldown { remaining } => {
            error_response(429, "cooldown", &format!("Wait {remaining} seconds"))
        }
        SessionError::Other(msg) => {
            let msg = if debug_mode {
                msg
            } else {
                "Request failed".to_string()
            };
            error_response(400, "error", &msg)
        }
    }
}
