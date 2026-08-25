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

use super::{SessionError, SessionManager, SessionState};
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

impl SessionManager {
    // ── Pending login management ────────────────────────────────────────

    /// Create a new pending login challenge. Does NOT touch active sessions.
    /// A subsequent call with the same `(uuid, ip)` replaces the previous one.
    pub async fn create_pending(
        &self,
        uuid: Uuid,
        aes_key: [u8; 32],
        client_ip: IpAddr,
    ) -> Result<u64, &'static str> {
        let nonce = crate::crypto::generate_nonce();
        self.pending_logins.lock().await.insert(
            (uuid, client_ip),
            SessionState::PendingVerify {
                nonce,
                aes_key,
                created_at: std::time::Instant::now(),
                client_ip,
            },
        );
        Ok(nonce)
    }

    /// Look up and consume the pending login for `(uuid, ip)`, verifying that
    /// the auth cipher decrypts to the stored nonce. Returns `(nonce, aes_key)`.
    pub async fn extract_pending_login(
        &self,
        auth: &Auth,
        client_ip: IpAddr,
    ) -> Result<(u64, [u8; 32]), SessionError> {
        let key = (auth.uuid, client_ip);
        let mut pending = self.pending_logins.lock().await;

        let (nonce, aes_key) = match pending.get(&key) {
            Some(SessionState::PendingVerify { nonce, aes_key, .. }) => (*nonce, *aes_key),
            _ => {
                return Err(SessionError::from(
                    "no pending login for this (uuid, ip)",
                ));
            }
        };

        // Verify the nonce by decrypting the auth hex with the stored AES key.
        let cipher_bytes = hex::decode(auth.hex()).map_err(|_| {
            SessionError::from("invalid hex in auth cipher")
        })?;
        if cipher_bytes.len() != 16 {
            return Err(SessionError::from("invalid cipher length"));
        }
        let mut cipher_arr = [0u8; 16];
        cipher_arr.copy_from_slice(&cipher_bytes);
        let plaintext = crate::crypto::decrypt_aes_cbc(&cipher_arr, &aes_key).map_err(|_| {
            SessionError::from("decryption failed — wrong AES key?")
        })?;
        let extracted_nonce = crate::crypto::u64_from_be_bytes(&plaintext);
        if extracted_nonce != nonce {
            pending.remove(&key); // consume on mismatch too — one shot
            return Err(SessionError::from("nonce mismatch"));
        }

        pending.remove(&key);
        drop(pending);
        Ok((nonce, aes_key))
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
        client_ip: IpAddr,
        discord_rpc: &DiscordSocialRpc,
        access_token: &str,
        cooldown_secs: u64,
        user_info: Option<UserInfo>,
    ) -> Result<u64, SessionError> {
        // Find the pending login for this (uuid, ip) and verify the nonce.
        let (nonce, aes_key) = self.extract_pending_login(auth, client_ip).await?;

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
            log::info!(
                "evt=session_reused uuid={} ip={client_ip}",
                auth.uuid
            );
        } else {
            // First connection (or previous session already cleaned up):
            // create a new Discord client and register a fresh session.
            let client = self
                .create_and_start_client(discord_rpc, access_token)
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

    async fn promote_to_active(
        &self,
        meta: ActiveSessionMeta,
        client: Arc<DiscordRpcClient>,
    ) {
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