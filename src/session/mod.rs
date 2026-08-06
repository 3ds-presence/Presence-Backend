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

mod activity;
mod cleanup;
mod consent;
mod error;
mod state;
mod verify;

pub use error::{session_error_into_response, SessionError};
pub use state::SessionState;

use std::collections::HashMap;
use std::net::IpAddr;

use tokio::sync::Mutex;
use uuid::Uuid;

/// Timeout for pending verification sessions (seconds).
const PENDING_TIMEOUT_SECS: u64 = 30;
/// Timeout for pending consent sessions (seconds).
const PENDING_CONSENT_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// Manages all active and pending sessions, with IP-based rate limiting.
pub struct SessionManager {
    sessions: Mutex<HashMap<Uuid, SessionState>>,
    ip_counts: Mutex<HashMap<IpAddr, usize>>,
    /// Pending consent sessions indexed by `temp_token`.
    consent_sessions: Mutex<HashMap<Uuid, Uuid>>, // temp_token -> session uuid
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ip_counts: Mutex::new(HashMap::new()),
            consent_sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Decrement the IP counter for a given address.
    fn decrement_ip(ip_counts: &mut HashMap<IpAddr, usize>, ip: IpAddr) {
        match ip_counts.get_mut(&ip) {
            Some(count) if *count > 1 => *count -= 1,
            _ => {
                ip_counts.remove(&ip);
            }
        }
    }

    /// Remove a session by UUID, decrement IP counter, and return its state.
    pub async fn remove_session(&self, uuid: &Uuid) -> Option<SessionState> {
        let state = self.sessions.lock().await.remove(uuid);
        if let Some(ref s) = state {
            self.remove_consent_mapping(s).await;
            let mut ip_counts = self.ip_counts.lock().await;
            let ip = s.client_ip();
            Self::decrement_ip(&mut ip_counts, ip);
        }
        state
    }

    /// If the state is `PendingConsent`, remove the `temp_token` -> uuid mapping.
    async fn remove_consent_mapping(&self, state: &SessionState) {
        if let SessionState::PendingConsent { temp_token, .. } = state {
            self.consent_sessions.lock().await.remove(temp_token);
        }
    }
}