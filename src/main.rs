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

    // Create the global DiscordSocialRpcAdmin instance
    info!("DiscordSocialRpcAdmin initialized for app_id={}", config.client_id);
    let discord_rpc = DiscordSocialRpcAdmin::new(&config.client_id, &config.client_secret)
        .expect("Failed to create DiscordSocialRpcAdmin");

    // Create session manager
    let session_manager = Arc::new(SessionManager::new());

    // Initialize activity generator (in-memory catalogue of game metadata)
    let activity_generator = ActivityGenerator::new(&config.script_dir, &config.assets_base_url, &config.mii_generator_server);

    // Create shared state
    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        discord_rpc,
        session_manager: session_manager.clone(),
        activity_generator,
    });

    // Start background tasks
    let timeout_session_manager = session_manager.clone();
    tokio::spawn(async move {
        tasks::timeout::run(timeout_session_manager, 60).await;
    });

    let refresh_db = state.db.clone();
    let refresh_admin = state.discord_rpc.clone();
    tokio::spawn(async move {
        tasks::token_refresh::run(refresh_db, refresh_admin).await;
    });

    // Build router
    let app = Router::new()
        .route("/register", post(routes::register::handler))
        .route("/login", post(routes::login::handler))
        .route("/login/verify", post(routes::login_verify::handler))
        .route("/activity/set", post(routes::activity::set_handler))
        .route("/activity/heartbeat", post(routes::activity::heartbeat_handler))
        .route("/logout", post(routes::logout::handler))
        .route("/reset_aes", post(routes::reset_aes::handler))
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