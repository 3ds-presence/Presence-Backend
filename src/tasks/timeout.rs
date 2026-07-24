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
use uuid::Uuid;

use crate::session::SessionManager;

/// Periodic cleanup of sessions inactive for `timeout_secs`.
pub async fn run(session_manager: Arc<SessionManager>, timeout_secs: u64) {
    info!("timeout task started (timeout={timeout_secs}s)");

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;

        let expired = session_manager
            .get_expired_active_sessions(timeout_secs)
            .await;

        for uuid in expired {
            stop_client_activity(&session_manager, &uuid).await;
            session_manager.remove_session(&uuid).await;
            info!("session {uuid}: cleaned up due to inactivity");
        }
    }
}

/// If a Discord client exists for this session, stop its activity.
async fn stop_client_activity(session_manager: &SessionManager, uuid: &Uuid) {
    let Some(client) = session_manager.get_client(uuid).await else {
        return;
    };
    let _ = tokio::task::spawn_blocking(move || {
        let _ = client.stop_activity();
    })
    .await;
}
