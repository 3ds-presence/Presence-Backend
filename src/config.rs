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
    /// Directory containing game metadata (title_id/meta.json).
    pub info_dir: String,
    /// URL of the Mii generator server (e.g. "http://localhost:8080/miis/").
    pub mii_generator_server: String,
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
            info_dir: env::var("INFO_DIR")
                .unwrap_or_else(|_| "activity_manager/info".to_string()),
            mii_generator_server: env::var("MII_GENERATOR_SERVER")
                .expect("MII_GENERATOR_SERVER must be set in .env"),
        }
    }
}
