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
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use discord_social_rpc::{DiscordRpcClient, DiscordSocialRpc};
use uuid::Uuid;

use activity_generator::UserInfo;
use crate::auth::Auth;
use crate::crypto;
use super::{SessionError, SessionManager, SessionState};

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

impl SessionManager {
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