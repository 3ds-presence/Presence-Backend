use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use log::info;
use sea_orm::DatabaseConnection;
use tokio::runtime::Runtime;

use discord_social_rpc::DiscordSocialRpc;

mod config;
mod crypto;
mod db;
mod models;
mod routes;
mod session;
mod tasks;

use config::Config;
use session::SessionManager;

/// Shared application state available to all route handlers.
pub struct AppState {
    pub config: Config,
    pub db: DatabaseConnection,
    pub discord_rpc: DiscordSocialRpc,
    pub session_manager: Arc<SessionManager>,
}

#[tokio::main]
async fn main() {
    // Load .env file
    dotenvy::dotenv().ok();
    env_logger::init();

    info!("3DS Presence Server starting...");

    // Load configuration
    let config = Config::from_env();
    info!("Configuration loaded");

    // Initialize database
    let db = db::init_database(&config.database_url)
        .await
        .expect("Failed to initialize database");
    info!("Database initialized: {}", config.database_url);

    // Create a tokio runtime for DiscordSocialRpc (shared runtime)
    let discord_runtime = Arc::new(Runtime::new().expect("Failed to create tokio runtime"));

    // Create the global DiscordSocialRpc instance
    info!("DiscordSocialRpc initialized for app_id={}", config.client_id);
    let discord_rpc = DiscordSocialRpc::with_runtime(&config.client_id, discord_runtime);

    // Create session manager
    let session_manager = Arc::new(SessionManager::new());

    // Create shared state
    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        discord_rpc,
        session_manager: session_manager.clone(),
    });

    // Start background tasks
    let timeout_session_manager = session_manager.clone();
    tokio::spawn(async move {
        tasks::timeout::run(timeout_session_manager, 60).await;
    });

    let refresh_db = state.db.clone();
    tokio::spawn(async move {
        tasks::token_refresh::run(refresh_db).await;
    });

    // Build router
    let app = Router::new()
        .route("/register", post(routes::register::handler))
        .route("/login", post(routes::login::handler))
        .route("/login/verify", post(routes::login_verify::handler))
        .route("/activity", post(routes::activity::handler))
        .route("/logout", post(routes::logout::handler))
        .with_state(state);

    // Start server
    let addr = &config.listen_addr;
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}