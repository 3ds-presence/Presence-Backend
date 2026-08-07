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

use serde::Deserialize;

/// Cloudflare Turnstile siteverify response.
#[derive(Deserialize)]
struct SiteVerifyResponse {
    success: bool,
}

/// Verify a Turnstile client token with Cloudflare's siteverify endpoint.
///
/// Returns `Ok(())` only when Cloudflare confirms the token is valid.
/// A network or HTTP failure is treated as a hard error (`Err`), not a silent pass.
pub async fn verify_turnstile(
    secret_key: &str,
    token: &str,
    remote_ip: Option<&str>,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    let mut params = vec![("secret", secret_key), ("response", token)];
    if let Some(ip) = remote_ip {
        params.push(("remoteip", ip));
    }

    let resp = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Turnstile siteverify request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Turnstile siteverify returned HTTP {}",
            resp.status()
        ));
    }

    let body: SiteVerifyResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Turnstile siteverify response: {e}"))?;

    if body.success {
        Ok(())
    } else {
        Err("Turnstile token invalid or already used".to_string())
    }
}