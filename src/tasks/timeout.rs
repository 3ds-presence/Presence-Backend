use std::sync::Arc;
use std::time::Duration;

use log::{info};

use crate::session::SessionManager;

/// Background task that checks for expired sessions every 10 seconds.
/// Active sessions with no activity for `timeout_secs` seconds are stopped.
pub async fn run(
    session_manager: Arc<SessionManager>,
    timeout_secs: u64,
) {
    info!("timeout task started (timeout={}s)", timeout_secs);

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Get expired session UUIDs
        let expired = session_manager.get_expired_active_sessions(timeout_secs).await;

        for uuid in expired {
            // Get the client and stop it
            if let Some(client) = session_manager.get_client(&uuid).await {
                let client_clone = client.clone();
                tokio::task::spawn_blocking(move || {
                    let _ = client_clone.stop_activity();
                }).await.ok();
            }

            // Remove the session
            session_manager.remove_session(&uuid).await;
            info!("session {}: cleaned up due to inactivity", uuid);
        }
    }
}