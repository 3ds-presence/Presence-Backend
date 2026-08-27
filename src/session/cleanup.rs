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

use discord_social_rpc::DiscordRpcClient;
use uuid::Uuid;

use super::{EncNonce, SessionManager, SessionState};

/// Timeout for pending login challenges (seconds).
const PENDING_TIMEOUT_SECS: u64 = 10;
/// Timeout for pending consent sessions (seconds).
const PENDING_CONSENT_TIMEOUT_SECS: u64 = 300; // 5 minutes

impl SessionManager {
    /// Return UUIDs of active sessions that have been inactive too long.
    /// `sessions` only contains `Active` entries, so no variant check needed.
    pub async fn get_expired_active_sessions(&self, timeout_secs: u64) -> Vec<Uuid> {
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .filter_map(|(uuid, state)| {
                if let SessionState::Active { last_activity, .. } = state {
                    (last_activity.elapsed().as_secs() > timeout_secs).then_some(*uuid)
                } else {
                    None
                }
            })
            .collect()
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
    pub(super) async fn remove_dead_session(&self, uuid: &Uuid) {
        self.terminate_session(uuid).await;
    }

    /// Return expired pending login keys for cleanup.
    pub async fn get_expired_pending_logins(&self) -> Vec<(Uuid, EncNonce)> {
        self.pending_logins
            .lock()
            .await
            .iter()
            .filter_map(|(key, state)| {
                let SessionState::PendingVerify { created_at, .. } = state else {
                    return None;
                };
                (created_at.elapsed().as_secs() > PENDING_TIMEOUT_SECS).then_some(key.clone())
            })
            .collect()
    }

    /// Return expired pending consents for cleanup.
    pub async fn get_expired_pending_consents(&self) -> Vec<Uuid> {
        self.pending_consents
            .lock()
            .await
            .iter()
            .filter_map(|(token, state)| {
                let SessionState::PendingConsent { created_at, .. } = state else {
                    return None;
                };
                (created_at.elapsed().as_secs() > PENDING_CONSENT_TIMEOUT_SECS).then_some(*token)
            })
            .collect()
    }

    /// Remove a pending login by its `(uuid, expected cipher)` key.
    pub async fn remove_pending_login(&self, uuid: Uuid, cipher: &EncNonce) {
        self.pending_logins
            .lock()
            .await
            .remove(&(uuid, cipher.to_owned()));
    }

    /// Remove a pending consent by token.
    pub async fn remove_pending_consent(&self, temp_token: &Uuid) {
        self.pending_consents.lock().await.remove(temp_token);
    }

    /// Remove an active session by UUID, decrement IP counter, and return its state.
    pub async fn remove_session(&self, uuid: &Uuid) -> Option<SessionState> {
        let state = self.sessions.lock().await.remove(uuid);
        if let Some(ref s) = state {
            let mut ip_counts = self.ip_counts.lock().await;
            let ip = s.client_ip();
            Self::decrement_ip(&mut ip_counts, ip);
        }
        state
    }
}