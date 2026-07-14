use std::sync::Arc;

use axum::{extract::State, Form};
use serde::Deserialize;

use axum::response::IntoResponse;

use crate::auth::Auth;
use crate::response::success_response;
use crate::AppState;

#[derive(Deserialize, Debug, Default)]
pub struct LogoutForm {
    pub uuid: String,
    pub auth_hex: String,
}

/// POST /logout — Stop the Discord activity for an active session and remove it.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LogoutForm>,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth = Auth::new(&form.uuid, &form.auth_hex)?;

    // Stop the activity via session manager
    state.session_manager
        .stop_activity(&auth, 0)
        .await
        .map_err(|e| e.into_response())?;

    Ok(success_response("success=true"))
}