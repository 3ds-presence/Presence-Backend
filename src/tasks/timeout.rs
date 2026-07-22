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

use log::{info};

use crate::session::SessionManager;

/// Background task that checks for expired sessions every 10 seconds.
/// Active sessions with no activity for `timeout_secs` seconds are stopped.
pub async fn run(
    session_manager: Arc<SessionManager>,
    timeout_secs: u64,
) {
    info!("timeout task started (timeout={}s)", timeout_secs);

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Get expired session UUIDs
        let expired = session_manager.get_expired_active_sessions(timeout_secs).await;

        for uuid in expired {
            // Get the client and stop it
            if let Some(client) = session_manager.get_client(&uuid).await {
                let client_clone = client.clone();
                tokio::task::spawn_blocking(move || {
                    let _ = client_clone.stop_activity();
                }).await.ok();
            }

            // Remove the session
            session_manager.remove_session(&uuid).await;
            info!("session {}: cleaned up due to inactivity", uuid);
        }
    }
}