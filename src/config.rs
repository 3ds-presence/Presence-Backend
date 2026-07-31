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

use std::env;

use crate::crypto;

/// Server configuration loaded from environment variables / .env file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Master key (AES-256) used to encrypt secrets at rest in the database.
    pub master_key: [u8; crypto::MASTER_KEY_LEN],
    /// Discord application ID (same as `OAuth2` client ID).
    pub client_id: String,
    /// Discord `OAuth2` client secret.
    pub client_secret: String,
    /// `OAuth2` redirect URI (must match Discord Developer Portal).
    pub redirect_uri: String,
    /// Database connection URL.
    pub database_url: String,
    /// Minimum seconds between two activity updates for the same client.
    pub activity_cooldown_secs: u64,
    /// Maximum number of concurrent sessions per IP address.
    pub max_clients_per_ip: usize,
    /// Server listen address.
    pub listen_addr: String,
    /// Base URL for game icon images (e.g. "<http://localhost:8080/imgs>/").
    pub assets_base_url: String,
    /// Directory containing game scripts (`title_id/script.lua`).
    pub scripts_dir: String,
    /// URL of the Mii generator server (e.g. "<http://localhost:8080/miis>/").
    pub mii_generator_server: String,
    /// Whether to expose detailed error messages (set to true when `RUST_LOG=debug`).
    pub debug_mode: bool,
    /// Custom cache capacity for `DiscordSocialRpc` (optional — uses default `::new()` if `None`).
    pub cache_capacity: Option<usize>,
    /// Custom cache eviction batch size for `DiscordSocialRpc` (optional — uses default `::new()` if `None`).
    pub cache_evict_batch: Option<usize>,
}

impl Config {
    /// Load configuration from environment variables.
    /// Call this after `dotenvy::dotenv()`.
    pub fn from_env() -> Self {
        let master_key_hex =
            env::var("MASTER_KEY").expect("MASTER_KEY must be set in .env (64 hex chars)");
        let master_key = crypto::parse_master_key(&master_key_hex)
            .expect("MASTER_KEY must be a valid 64-char hex string");

        Self {
            master_key,
            client_id: env::var("CLIENT_ID").expect("CLIENT_ID must be set in .env"),
            client_secret: env::var("CLIENT_SECRET").expect("CLIENT_SECRET must be set in .env"),
            redirect_uri: env::var("REDIRECT_URI").expect("REDIRECT_URI must be set in .env"),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:presence.db?mode=rwc".to_string()),
            activity_cooldown_secs: env::var("ACTIVITY_COOLDOWN_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            max_clients_per_ip: env::var("MAX_CLIENTS_PER_IP")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8),
            listen_addr: env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:5555".to_string()),
            assets_base_url: env::var("ASSETS_BASE_URL")
                .expect("ASSETS_BASE_URL must be set in .env"),
            scripts_dir: env::var("SCRIPTS_DIR").unwrap_or_else(|_| "/app/scripts".to_string()),
            mii_generator_server: env::var("MII_GENERATOR_SERVER")
                .expect("MII_GENERATOR_SERVER must be set in .env"),
            debug_mode: env::var("RUST_LOG")
                .is_ok_and(|v| v.to_lowercase().contains("debug")),
            cache_capacity: env::var("CACHE_CAPACITY").ok().and_then(|s| s.parse().ok()),
            cache_evict_batch: env::var("CACHE_EVICT_BATCH").ok().and_then(|s| s.parse().ok()),
        }
    }
}
