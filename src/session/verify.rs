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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use discord_social_rpc::{DiscordRpcClient, DiscordSocialRpc};
use uuid::Uuid;

use super::{EncNonce, SessionError, SessionManager, SessionState};
use crate::auth::Auth;
use activity_generator::UserInfo;

/// Metadata for a new or updated active session — groups the params that
/// `promote_to_active` and `update_active_session` share.
struct ActiveSessionMeta {
    uuid: Uuid,
    aes_key: [u8; 32],
    nonce: u64,
    cooldown_secs: u64,
    client_ip: IpAddr,
    user_info: Option<UserInfo>,
}

/// Everything [`SessionManager::verify_and_activate`] needs beyond the auth
/// cipher, grouped so the call site stays readable.
pub struct ActivateSessionParams<'a> {
    pub aes_key: [u8; 32],
    pub client_ip: IpAddr,
    pub discord_rpc: &'a DiscordSocialRpc,
    pub access_token: &'a str,
    pub cooldown_secs: u64,
    pub user_info: Option<UserInfo>,
}

impl SessionManager {
    // ── Pending login management ────────────────────────────────────────

    pub async fn create_pending(
        &self,
        uuid: Uuid,
        aes_key: [u8; 32],
        client_ip: IpAddr,
    ) -> u64 {
        let nonce = crate::crypto::generate_nonce();
        let expected_cipher: EncNonce = crate::crypto::encrypt_login_challenge(nonce, &aes_key);
        self.pending_logins.lock().await.insert(
            (uuid, expected_cipher),
            SessionState::PendingVerify {
                nonce,
                created_at: std::time::Instant::now(),
                client_ip,
            },
        );
        nonce
    }

    /// Consume the pending login matching the submitted cipher, if any.
    ///
    /// Pure hash-map lookup on `(uuid, submitted hex)` — no decryption. The
    /// UUID being part of the key, any hit necessarily belongs to this account;
    /// only a holder of its AES key can have produced a matching `EncNonce`.
    ///
    /// On success, every other pending challenge attached to this UUID is
    /// purged: they are all bogus by definition (spam, stale retries), so a
    /// single legitimate connection wipes the attacker's flood clean.
    pub async fn extract_pending_login(
        &self,
        auth: &Auth,
        client_ip: IpAddr,
    ) -> Result<u64, SessionError> {
        let submitted: EncNonce = auth.hex().to_lowercase();
        let mut pending = self.pending_logins.lock().await;

        if let Some(SessionState::PendingVerify { nonce, .. }) = pending.remove(&(auth.uuid, submitted)) {
            let before = pending.len();
            pending.retain(|(u, _), _| u != &auth.uuid);
            let purged = before - pending.len();
            drop(pending);
            if purged > 0 {
                log::info!(
                    "evt=pending_challenges_purged uuid={} count={purged}",
                    auth.uuid
                );
            }
            Ok(nonce)
        } else {
            log::warn!(
                "evt=pending_login_miss uuid={} requested_ip={client_ip}",
                auth.uuid
            );
            Err(SessionError::from(
                "no pending login for this (uuid, cipher)",
            ))
        }
    }

    // ── Login verification ──────────────────────────────────────────────

    /// Verify a pending login challenge and promote/update the active session.
    ///
    /// If a session is already active for this UUID (re-login: the 3DS
    /// disconnected without logout then reconnected), the existing Discord
    /// gateway client is **reused** — no expensive disconnect/reconnect.
    pub async fn verify_and_activate(
        &self,
        auth: &Auth,
        params: ActivateSessionParams<'_>,
    ) -> Result<u64, SessionError> {
        let ActivateSessionParams {
            aes_key,
            client_ip,
            discord_rpc,
            access_token,
            cooldown_secs,
            user_info,
        } = params;

        // Look up and consume the pending challenge keyed by the expected
        // cipher the client just submitted.
        let nonce = self.extract_pending_login(auth, client_ip).await?;

        // Check whether there is already an active session for this UUID.
        let existing_client = {
            let sessions = self.sessions.lock().await;
            match sessions.get(&auth.uuid) {
                Some(SessionState::Active { client, .. }) => Some(client.clone()),
                _ => None,
            }
        };

        if let Some(client) = existing_client {
            // Re-login: just update the metadata in-place. The Discord
            // gateway connection is still alive, so there is nothing to
            // tear down or rebuild.
            let meta = ActiveSessionMeta {
                uuid: auth.uuid,
                aes_key,
                nonce,
                cooldown_secs,
                client_ip,
                user_info,
            };
            self.update_active_session(meta, client).await;
            log::info!("evt=session_reused uuid={} ip={client_ip}", auth.uuid);
        } else {
            // First connection (or previous session already cleaned up):
            // create a new Discord client and register a fresh session.
            let client = self
                .create_and_start_client(discord_rpc, access_token, auth.uuid)
                .await?;
            let meta = ActiveSessionMeta {
                uuid: auth.uuid,
                aes_key,
                nonce,
                cooldown_secs,
                client_ip,
                user_info,
            };
            self.promote_to_active(meta, client).await;
            log::info!(
                "evt=discord_gateway_started uuid={} ip={client_ip}",
                auth.uuid
            );
        }

        Ok(nonce)
    }

    // ── Helpers ──────────────────────────────────────────────────────

    async fn create_and_start_client(
        &self,
        discord_rpc: &DiscordSocialRpc,
        access_token: &str,
        uuid: Uuid,
    ) -> Result<Arc<DiscordRpcClient>, SessionError> {
        let client = discord_rpc
            .create_new_client_with_tag(access_token, Some(uuid.to_string()))
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

    async fn promote_to_active(&self, meta: ActiveSessionMeta, client: Arc<DiscordRpcClient>) {
        // Increment IP count for the new active session.
        {
            let mut ip_counts = self.ip_counts.lock().await;
            *ip_counts.entry(meta.client_ip).or_insert(0) += 1;
        }
        let last_activity = Instant::now()
            .checked_sub(Duration::from_secs(meta.cooldown_secs + 1))
            .unwrap();
        self.sessions.lock().await.insert(
            meta.uuid,
            SessionState::Active {
                client,
                aes_key: meta.aes_key,
                last_counter: AtomicU64::new(meta.nonce),
                last_activity,
                client_ip: meta.client_ip,
                user_info: meta.user_info,
            },
        );
    }

    /// Update an already-active session in-place. If the IP changed, adjust
    /// the IP counters accordingly. Preserves the existing Discord client.
    async fn update_active_session(
        &self,
        meta: ActiveSessionMeta,
        _client: Arc<DiscordRpcClient>, // kept alive by the session entry
    ) {
        let last_activity = Instant::now()
            .checked_sub(Duration::from_secs(meta.cooldown_secs + 1))
            .unwrap();

        let mut sessions = self.sessions.lock().await;
        let old_ip = match sessions.get(&meta.uuid) {
            Some(SessionState::Active { client_ip, .. }) => *client_ip,
            _ => {
                // Session disappeared — unexpected but not fatal.
                return;
            }
        };

        // Adjust IP counters if the IP changed.
        if old_ip != meta.client_ip {
            drop(sessions);
            let mut ip_counts = self.ip_counts.lock().await;
            Self::decrement_ip(&mut ip_counts, old_ip);
            *ip_counts.entry(meta.client_ip).or_insert(0) += 1;
            drop(ip_counts);
            sessions = self.sessions.lock().await;
        }

        if let Some(SessionState::Active {
            aes_key: s_aes_key,
            last_counter,
            last_activity: s_last_activity,
            client_ip: s_client_ip,
            user_info: s_user_info,
            ..
        }) = sessions.get_mut(&meta.uuid)
        {
            *s_aes_key = meta.aes_key;
            last_counter.store(meta.nonce, Ordering::SeqCst);
            *s_last_activity = last_activity;
            *s_client_ip = meta.client_ip;
            *s_user_info = meta.user_info.or_else(|| s_user_info.clone());
        }
    }
}
