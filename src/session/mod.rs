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
mod read;
mod state;
mod verify;

pub use error::{session_error_into_response, SessionError};
pub use state::SessionState;
pub use verify::ActivateSessionParams;

use std::collections::HashMap;
use std::net::IpAddr;

use tokio::sync::Mutex;
use uuid::Uuid;

/// Hex-encoded expected login challenge: `AES-256-CBC(nonce)` under the
/// account key, computed server-side at `/login`. A legitimate client sends
/// back exactly this value; only a holder of the AES key can produce it.
pub type EncNonce = String;

/// Manages all active and pending sessions, with IP-based rate limiting.
///
/// Three independent stores:
///
/// * `sessions` — active sessions only (one per UUID).
/// * `pending_logins` — login challenges keyed by `(Uuid, EncNonce)`.
/// * `pending_consents` — RGPD consent sessions, keyed by `temp_token`.
pub struct SessionManager {
    /// Active sessions, exactly one per UUID. Contains only `SessionState::Active`.
    sessions: Mutex<HashMap<Uuid, SessionState>>,
    ip_counts: Mutex<HashMap<IpAddr, usize>>,
    /// Pending login challenges keyed by `(owner UUID, expected cipher)`. Only
    /// a holder of the account's AES key can produce a matching `EncNonce`, so
    /// possession of the key remains the sole proof of identity.
    pending_logins: Mutex<HashMap<(Uuid, EncNonce), SessionState>>,
    /// Pending consent sessions indexed by `temp_token`.
    pending_consents: Mutex<HashMap<Uuid, SessionState>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ip_counts: Mutex::new(HashMap::new()),
            pending_logins: Mutex::new(HashMap::new()),
            pending_consents: Mutex::new(HashMap::new()),
        }
    }

    fn decrement_ip(ip_counts: &mut HashMap<IpAddr, usize>, ip: IpAddr) {
        match ip_counts.get_mut(&ip) {
            Some(count) if *count > 1 => *count -= 1,
            _ => {
                ip_counts.remove(&ip);
            }
        }
    }
}
