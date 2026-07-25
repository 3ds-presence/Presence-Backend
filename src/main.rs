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
    env_logger::init();
    info!("3DS Presence Server starting...");

    let config = load_config();
    let db = init_database(&config).await;
    let discord_rpc = init_discord_rpc(&config);
    let session_manager = Arc::new(SessionManager::new());
    let activity_generator = init_activity_generator(&config);
    let state = build_state(
        &config,
        db,
        discord_rpc,
        session_manager.clone(),
        activity_generator,
    );

    spawn_timeout_task(session_manager.clone());
    spawn_token_refresh_task(&state);

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
    info!(
        "DiscordSocialRpcAdmin initialized for app_id={}",
        config.client_id
    );
    DiscordSocialRpcAdmin::new(&config.client_id, &config.client_secret)
        .expect("Failed to create DiscordSocialRpcAdmin")
}

/// Initialize the activity generator for building Discord Presence.
fn init_activity_generator(config: &Config) -> ActivityGenerator {
    ActivityGenerator::new(
        &config.scripts_dir,
        &config.assets_base_url,
        &config.mii_generator_server,
    )
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
    tokio::spawn(async move {
        tasks::token_refresh::run(refresh_db, refresh_admin).await;
    });
}

/// Build the Axum router with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/register", post(routes::register::handler))
        .route("/login", post(routes::login::handler))
        .route("/login/verify", post(routes::login_verify::handler))
        .route("/activity/set", post(routes::activity::set_handler))
        .route(
            "/activity/heartbeat",
            post(routes::activity::heartbeat_handler),
        )
        .route("/logout", post(routes::logout::handler))
        .route("/reset_aes", post(routes::reset_aes::handler))
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
