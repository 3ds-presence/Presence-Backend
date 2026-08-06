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

use super::{SessionManager, SessionState, PENDING_CONSENT_TIMEOUT_SECS, PENDING_TIMEOUT_SECS};

impl SessionManager {
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
    pub(super) async fn remove_dead_session(&self, uuid: &Uuid) {
        self.terminate_session(uuid).await;
    }
}