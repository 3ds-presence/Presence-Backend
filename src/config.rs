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

/// Server configuration loaded from environment variables / .env file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Discord application ID (same as OAuth2 client ID).
    pub client_id: String,
    /// Discord OAuth2 client secret.
    pub client_secret: String,
    /// OAuth2 redirect URI (must match Discord Developer Portal).
    pub redirect_uri: String,
    /// Database connection URL.
    pub database_url: String,
    /// Minimum seconds between two activity updates for the same client.
    pub activity_cooldown_secs: u64,
    /// Maximum number of concurrent sessions per IP address.
    pub max_clients_per_ip: usize,
    /// Server listen address.
    pub listen_addr: String,
    /// Base URL for game icon images (e.g. "http://localhost:8080/imgs/").
    pub assets_base_url: String,
    /// Directory containing game scripts (title_id/script.lua).
    pub scripts_dir: String,
    /// URL of the Mii generator server (e.g. "http://localhost:8080/miis/").
    pub mii_generator_server: String,
    /// Maximum number of Lua VMs to keep in the pool for activity scripts (0 = default 64).
    pub lua_pool_max: usize,
    /// Whether to expose detailed error messages (set to true when RUST_LOG=debug).
    pub debug_mode: bool,
}

impl Config {
    /// Load configuration from environment variables.
    /// Call this after `dotenvy::dotenv()`.
    pub fn from_env() -> Self {
        Self {
            client_id: env::var("CLIENT_ID")
                .expect("CLIENT_ID must be set in .env"),
            client_secret: env::var("CLIENT_SECRET")
                .expect("CLIENT_SECRET must be set in .env"),
            redirect_uri: env::var("REDIRECT_URI")
                .expect("REDIRECT_URI must be set in .env"),
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
            listen_addr: env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:5555".to_string()),
            assets_base_url: env::var("ASSETS_BASE_URL")
                .expect("ASSETS_BASE_URL must be set in .env"),
            scripts_dir: env::var("SCRIPTS_DIR")
                .unwrap_or_else(|_| "/app/scripts".to_string()),
            mii_generator_server: env::var("MII_GENERATOR_SERVER")
                .expect("MII_GENERATOR_SERVER must be set in .env"),
            lua_pool_max: env::var("LUA_POOL_MAX")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(64),
            debug_mode: env::var("RUST_LOG")
                .map(|v| v.to_lowercase().contains("debug"))
                .unwrap_or(false),
        }
    }
}
