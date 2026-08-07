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

use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use axum::Router;
use log::info;
use sea_orm::DatabaseConnection;

use activity_generator::ActivityGenerator;
use discord_social_rpc::DiscordSocialRpcAdmin;

mod auth;
mod config;
mod crypto;
mod db;
mod logging;
mod middleware;
mod models;
mod response;
mod routes;
mod session;
mod tasks;
mod utils;
mod validation;

use config::Config;
use session::SessionManager;

/// Shared application state available to all route handlers.
pub struct AppState {
    pub config: Config,
    pub db: DatabaseConnection,
    pub discord_rpc: DiscordSocialRpcAdmin,
    pub session_manager: Arc<SessionManager>,
    pub activity_generator: ActivityGenerator,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    logging::init();
    info!("3DS Presence Server starting...");

    let config = load_config();
    let db = init_database(&config).await;
    let discord_rpc = init_discord_rpc(&config);
    let session_manager = Arc::new(SessionManager::new());
    let activity_generator = init_activity_generator(&config).await;
    let state = build_state(
        &config,
        db,
        discord_rpc,
        session_manager.clone(),
        activity_generator,
    );

    spawn_timeout_task(session_manager.clone());
    spawn_token_refresh_task(&state);
    spawn_cleanup_task(state.db.clone());

    let addr = state.config.listen_addr.clone();
    let app = build_router(state);
    start_server(app, &addr).await;
}

/// Load application configuration from environment variables.
fn load_config() -> Config {
    let config = Config::from_env();
    info!("Configuration loaded");
    config
}

/// Initialize the database connection.
async fn init_database(config: &Config) -> DatabaseConnection {
    let db = db::init_database(&config.database_url)
        .await
        .expect("Failed to initialize database");
    info!("Database initialized: {}", config.database_url);
    db
}

/// Initialize the Discord Social RPC admin client.
fn init_discord_rpc(config: &Config) -> DiscordSocialRpcAdmin {
    if let (Some(cap), Some(batch)) = (config.cache_capacity, config.cache_evict_batch) {
        info!(
            "DiscordSocialRpcAdmin initialized for app_id={} with custom cache (capacity={}, evict_batch={})",
            config.client_id, cap, batch
        );
        DiscordSocialRpcAdmin::new_custom_cached(
            &config.client_id,
            &config.client_secret,
            cap,
            batch,
        )
        .expect("Failed to create DiscordSocialRpcAdmin")
    } else {
        info!(
            "DiscordSocialRpcAdmin initialized for app_id={} (default, no custom cache)",
            config.client_id
        );
        DiscordSocialRpcAdmin::new(&config.client_id, &config.client_secret)
            .expect("Failed to create DiscordSocialRpcAdmin")
    }
}

/// Initialize the activity generator for building Discord Presence.
async fn init_activity_generator(config: &Config) -> ActivityGenerator {
    ActivityGenerator::new(
        &config.scripts_dir,
        &config.assets_base_url,
        &config.mii_generator_server,
    )
    .await
}

/// Build the shared application state.
fn build_state(
    config: &Config,
    db: DatabaseConnection,
    discord_rpc: DiscordSocialRpcAdmin,
    session_manager: Arc<SessionManager>,
    activity_generator: ActivityGenerator,
) -> Arc<AppState> {
    Arc::new(AppState {
        config: config.clone(),
        db,
        discord_rpc,
        session_manager,
        activity_generator,
    })
}

/// Spawn the background task that cleans up inactive sessions.
fn spawn_timeout_task(session_manager: Arc<SessionManager>) {
    tokio::spawn(async move {
        tasks::timeout::run(session_manager, 60).await;
    });
}

/// Spawn the background task that refreshes Discord tokens.
fn spawn_token_refresh_task(state: &Arc<AppState>) {
    let refresh_db = state.db.clone();
    let refresh_admin = state.discord_rpc.clone();
    let master_key = state.config.master_key;
    tokio::spawn(async move {
        tasks::token_refresh::run_with_master_key(refresh_db, refresh_admin, &master_key).await;
    });
}

/// Spawn the background task that deletes inactive accounts.
fn spawn_cleanup_task(db: sea_orm::DatabaseConnection) {
    tokio::spawn(async move {
        tasks::cleanup::run(db).await;
    });
}

/// Build the Axum router with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    // Payloads are small forms; cap body size to avoid unbounded memory use.
    const MAX_BODY_BYTES: usize = 16 * 1024;

    Router::new()
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(middleware::request_logger))
        .route("/register", post(routes::register::handler))
        .route("/confirm-consent", post(routes::confirm_consent::handler))
        .route("/reset_aes", post(routes::reset_aes::handler))
        .route("/account/delete", post(routes::delete_account::handler))
        .route("/account/export", post(routes::export_data::handler))
        .route("/3ds/login", post(routes::login::handler))
        .route("/3ds/login/verify", post(routes::login_verify::handler))
        .route("/3ds/activity/set", post(routes::activity::set_handler))
        .route(
            "/3ds/activity/heartbeat",
            post(routes::activity::heartbeat_handler),
        )
        .route("/3ds/logout", post(routes::logout::handler))
        .with_state(state)
}

/// Start the HTTP server on the configured address.
async fn start_server(app: Router, addr: &str) {
    info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");
    axum::serve(listener, app).await.expect("Server failed");
}
