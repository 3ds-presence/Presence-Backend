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

use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::response::error_response;

/// Custom session error type.
#[derive(Debug)]
pub enum SessionError {
    SessionNotFound,
    PendingNotActive,
    AuthFailed(String),
    ReplayDetected { counter: u64, last: u64 },
    Cooldown { remaining: u64 },
    /// The Discord `OAuth2` token was revoked or rejected by Discord.
    TokenRevoked,
    Other(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "session not found"),
            Self::PendingNotActive => write!(f, "session is pending verification, not active"),
            Self::AuthFailed(msg) => write!(f, "auth verification failed: {msg}"),
            Self::ReplayDetected { counter, last } => {
                write!(f, "replay detected: counter {counter} <= last {last}")
            }
            Self::Cooldown { remaining } => write!(f, "cooldown: wait {remaining} seconds"),
            Self::TokenRevoked => write!(f, "Discord OAuth2 token revoked"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        session_error_to_response(self, false, None)
    }
}

impl From<&str> for SessionError {
    fn from(s: &str) -> Self {
        Self::Other(s.to_string())
    }
}

impl From<String> for SessionError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

/// Map a session error to a safe response, logging security-relevant events
/// with an `evt=...` marker and the session `uuid` when available. The request
/// middleware enriches every line with `req_id`/`ip`/`path`, so a forensic
/// timeline of an attack can be reconstructed with a single grep.
fn session_error_to_response(err: SessionError, debug_mode: bool, uuid: Option<&Uuid>) -> Response {
    let uid_str = uuid.map_or_else(|| "unknown".to_string(), ToString::to_string);
    match err {
        SessionError::SessionNotFound | SessionError::PendingNotActive => {
            log::debug!("evt=session_not_found uuid={uid_str}");
            error_response(
                401,
                "session_expired",
                "Session expired or not found. Please re-login.",
            )
        }
        SessionError::TokenRevoked => {
            log::warn!("evt=token_revoked uuid={uid_str}");
            error_response(
                401,
                "token_revoked",
                "Discord OAuth2 token revoked. Please re-login.",
            )
        }
        SessionError::AuthFailed(msg) => {
            log::warn!("evt=auth_failed uuid={uid_str} reason=\"{msg}\"");
            let client_msg = if debug_mode {
                format!("auth verification failed: {msg}")
            } else {
                "Authentication failed".to_string()
            };
            error_response(403, "auth_failed", &client_msg)
        }
        SessionError::ReplayDetected { counter, last } => {
            log::warn!("evt=replay_detected uuid={uid_str} counter={counter} last={last}");
            let client_msg = if debug_mode {
                format!("replay detected: counter {counter} <= last {last}")
            } else {
                "Replay detected".to_string()
            };
            error_response(403, "replay_detected", &client_msg)
        }
        SessionError::Cooldown { remaining } => {
            log::debug!("evt=cooldown uuid={uid_str} remaining={remaining}");
            error_response(429, "cooldown", &format!("Wait {remaining} seconds"))
        }
        SessionError::Other(msg) => {
            log::warn!("evt=session_error uuid={uid_str} reason=\"{msg}\"");
            let client_msg = if debug_mode {
                msg
            } else {
                "Request failed".to_string()
            };
            error_response(400, "error", &client_msg)
        }
    }
}

/// Public wrapper used by routes to convert a `SessionError` into a response,
/// with optional verbose messages in debug mode. Pass `uuid` when known so
/// security events are attributed to the right account.
pub fn session_error_into_response(
    err: SessionError,
    debug_mode: bool,
    uuid: Option<&Uuid>,
) -> Response {
    session_error_to_response(err, debug_mode, uuid)
}