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

use axum::extract::State;
use axum::http::HeaderMap;
use axum::{extract::Form, response::Response};
use log::warn;
use serde::Deserialize;

use crate::response::{error_response, success_response};
use crate::utils::turnstile;
use crate::utils;
use crate::validation;
use crate::AppState;

#[derive(Deserialize)]
pub struct OauthStartForm {
    pub turnstile_token: Option<String>,
}

/// POST /oauth/start — Verify the Turnstile challenge (if enabled), issue a
/// one-time `OAuth2` `state`, and return the Discord authorization URL.
///
/// The returned URL always contains a fresh `state`. A state is only created
/// after a valid Turnstile token (when the captcha is enabled), so Discord
/// codes can never be exchanged without first passing the challenge.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<OauthStartForm>,
) -> Result<Response, Response> {
    let client_ip = utils::net::extract_client_ip(&headers)
        .map(|ip| ip.to_string());

    let turnstile_enabled = !state.config.turnstile_secret_key.is_empty();

    // If Turnstile is enabled, the challenge must pass before we issue a
    // state. On failure the request is rejected, so reaching this point
    // always means the captcha (if any) was valid.
    if turnstile_enabled {
        let token = form
            .turnstile_token
            .ok_or_else(|| error_response(400, "missing_turnstile_token", "Turnstile token is required"))?;
        let token = validation::validate_turnstile_token(&token)?.to_owned();

        turnstile::verify_turnstile(&state.config.turnstile_secret_key, &token, client_ip.as_deref())
            .await
            .map_err(|e| {
                warn!("evt=turnstile_failed ip={client_ip:?} reason={e}");
                error_response(403, "turnstile_failed", "Captcha verification failed")
            })?;
    }

    let state_value = state.oauth_state_store.create(true);

    let url = format!(
        "https://discord.com/oauth2/authorize?client_id={}&response_type=code&redirect_uri={}&scope=sdk.social_layer_presence&state={}",
        state.config.client_id,
        urlencoding::encode(&state.config.redirect_uri),
        state_value
    );

    log::info!("evt=oauth_started state_issued={state_value}");
    Ok(success_response(format!("url={}", urlencoding::encode(&url))))
}