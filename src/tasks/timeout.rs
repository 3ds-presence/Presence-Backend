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

/// Periodic cleanup of sessions inactive for `timeout_secs`.
pub async fn run(session_manager: Arc<SessionManager>, timeout_secs: u64) {
    info!("evt=timeout_task_started timeout={timeout_secs}s");

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;

        let expired = session_manager
            .get_expired_active_sessions(timeout_secs)
            .await;

        for uuid in expired {
            session_manager.terminate_session(&uuid).await;
            info!("evt=session_timeout uuid={uuid}");
        }
    }
}