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

use std::time::Instant;

use uuid::Uuid;

use super::{SessionManager, SessionState};

impl SessionManager {
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
}