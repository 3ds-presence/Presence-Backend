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

use axum::body::Body;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::{Deserialize, Serialize};

use crate::auth::Auth;
use crate::db;
use crate::models;
use crate::response::{error_response, AppError};
use crate::AppState;

#[derive(Deserialize)]
pub struct ExportQuery {
    pub uuid: String,
    pub auth_hex: String,
}

#[derive(Serialize)]
pub struct ExportData {
    pub uuid: String,
    pub discord_id: String,
    pub created_at: i64,
    pub last_connected: i64,
}

/// GET /account/export — Export user data (without secrets).
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, Response> {
    let auth = Auth::new(&query.uuid, &query.auth_hex)?;
    let user = fetch_and_auth_user(&state, &auth).await?;
    let json = build_export_json(&user, state.config.debug_mode)?;
    Ok(build_json_response(&json))
}

/// Fetch the user from DB and verify the session.
async fn fetch_and_auth_user(
    state: &Arc<AppState>,
    auth: &Auth,
) -> Result<models::Model, Response> {
    let user = db::get_user_by_uuid(&state.db, &auth.uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database query failed"))?
        .ok_or_else(|| error_response(404, "not_found", "User not found"))?;

    state
        .session_manager
        .heartbeat(auth, state.config.activity_cooldown_secs)
        .await
        .map_err(|e| {
            let msg = if state.config.debug_mode {
                e.to_string()
            } else {
                "Authentication failed".to_string()
            };
            error_response(403, "auth_failed", &msg)
        })?;

    Ok(user)
}

/// Build the JSON string from export data.
fn build_export_json(user: &models::Model, debug: bool) -> Result<String, AppError> {
    let data = ExportData {
        uuid: user.uuid.clone(),
        discord_id: user.discord_id.clone(),
        created_at: user.created_at,
        last_connected: user.last_connected,
    };

    serde_json::to_string(&data).map_err(|e| {
        let msg = if debug {
            format!("{e}")
        } else {
            "Failed to serialize data".to_string()
        };
        AppError(Box::new(error_response(500, "serialization_error", &msg)))
    })
}

/// Build the HTTP JSON response.
fn build_json_response(json: &str) -> Response {
    Response::builder()
        .header("Content-Type", "application/json")
        .header(
            "Content-Disposition",
            "attachment; filename=\"3ds-presence-export.json\"",
        )
        .body(Body::from(json.to_string()))
        .unwrap()
}