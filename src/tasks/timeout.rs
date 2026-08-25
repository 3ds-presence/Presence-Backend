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
use std::time::Duration;

use log::info;

use crate::session::SessionManager;

/// Periodic cleanup of all three stores:
///
/// * `sessions` — inactive active sessions (idle timeout).
/// * `pending_logins` — expired login challenges (>30 s).
/// * `pending_consents` — expired consent sessions (>5 min).
pub async fn run(session_manager: Arc<SessionManager>, timeout_secs: u64) {
    info!("evt=timeout_task_started timeout={timeout_secs}s");

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Clean up expired active sessions.
        let expired = session_manager
            .get_expired_active_sessions(timeout_secs)
            .await;
        for uuid in expired {
            session_manager.terminate_session(&uuid).await;
            info!("evt=session_timeout uuid={uuid}");
        }

        // Clean up expired pending login challenges.
        let expired_logins = session_manager.get_expired_pending_logins().await;
        for (uuid, ip) in expired_logins {
            session_manager.remove_pending_login(uuid, ip).await;
        }

        // Clean up expired pending consent sessions.
        let expired_consents = session_manager.get_expired_pending_consents().await;
        for temp_token in expired_consents {
            session_manager.remove_pending_consent(&temp_token).await;
            info!("evt=pending_consent_timeout temp_token={temp_token}");
        }
    }
}