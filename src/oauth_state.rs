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

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;

/// Each `OAuth2` state entry knows whether the caller passed a valid
/// Turnstile challenge before the state was issued.
#[derive(Clone)]
pub struct OauthStateEntry {
    pub turnstile_ok: bool,
    pub created_at: i64,
}

/// In-memory store of one-time, expiring `OAuth2` `state` values.
///
/// A state is only ever issued through `create()` and is consumed exactly
/// once via `consume()`. Unknown, reused, or expired states are rejected.
/// This guarantees that a Discord code can only be exchanged after a state
/// that was backed by a valid Turnstile challenge (when Turnstile is enabled).
pub struct OauthStateStore {
    inner: Mutex<HashMap<String, OauthStateEntry>>,
}

/// Time-to-live for a state entry, in seconds (5 minutes).
pub const STATE_TTL_SECS: i64 = 300;
/// Length of a generated state value (32 hex chars = 16 random bytes).
pub const STATE_LEN: usize = 32;

impl OauthStateStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a random state and store it, returning the hex value.
    pub fn create(&self, turnstile_ok: bool) -> String {
        let state_bytes: [u8; STATE_LEN / 2] = rand::rng().random();
        let state = hex::encode(state_bytes);

        let entry = OauthStateEntry {
            turnstile_ok,
            created_at: now_secs(),
        };

        self.inner.lock().unwrap().insert(state.clone(), entry);
        state
    }

    /// Atomically consume a state. Returns `None` if unknown, already used,
    /// or expired. The entry is removed in every case so it cannot be replayed.
    pub fn consume(&self, state: &str) -> Option<OauthStateEntry> {
        let entry;
        {
            let mut map = self.inner.lock().unwrap();
            entry = map.remove(state)?;
        }

        let now = now_secs();
        if now - entry.created_at > STATE_TTL_SECS {
            return None;
        }
        Some(entry)
    }

    /// Remove expired entries. Called periodically by a background task.
    pub fn cleanup(&self) {
        let now = now_secs();
        let mut map = self.inner.lock().unwrap();
        map.retain(|_, entry| now - entry.created_at <= STATE_TTL_SECS);
    }

    /// Number of live (non-expired) entries — used for tests/metrics.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.cleanup();
        self.inner.lock().unwrap().len()
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_consume_works() {
        let store = OauthStateStore::new();
        let state = store.create(true);
        assert_eq!(state.len(), STATE_LEN);

        let entry = store.consume(&state).expect("should consume");
        assert!(entry.turnstile_ok);

        // Second consume must fail (one-time).
        assert!(store.consume(&state).is_none());
    }

    #[test]
    fn unknown_state_is_rejected() {
        let store = OauthStateStore::new();
        let unknown = "a".repeat(STATE_LEN);
        assert!(store.consume(&unknown).is_none());
    }

    #[test]
    fn expired_state_is_rejected() {
        let store = OauthStateStore::new();
        let state = store.create(true);

        // Backdate the entry past the TTL.
        {
            let mut map = store.inner.lock().unwrap();
            if let Some(entry) = map.get_mut(&state) {
                entry.created_at -= STATE_TTL_SECS + 1;
            }
        }

        assert!(store.consume(&state).is_none());
    }
}