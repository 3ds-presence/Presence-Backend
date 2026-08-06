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

use axum::response::Response;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

use crate::crypto;
use crate::db;
use crate::models;
use crate::response::error_response;

/// Fetch a user by UUID, mapping DB errors to a 500 and missing users to a 404.
pub async fn fetch_user_or_404(
    db: &DatabaseConnection,
    uuid: &Uuid,
) -> Result<models::Model, Response> {
    db::get_user_by_uuid(db, uuid)
        .await
        .map_err(|_e| error_response(500, "db_error", "Database error"))?
        .ok_or_else(|| error_response(404, "user_not_found", "User not found"))
}

/// Verify that the supplied AES key (hex) matches the user's stored key.
///
/// The stored key is encrypted at rest, so it is decrypted before the
/// constant-time comparison. `debug_mode` only changes the error message;
/// the status code and error code are identical either way.
///
/// On success, returns the authenticated user so callers don't need a
/// second database fetch.
pub async fn authenticate_aes_key(
    db: &DatabaseConnection,
    master_key: &[u8; crypto::MASTER_KEY_LEN],
    uuid: &Uuid,
    supplied_key_hex: &str,
    debug_mode: bool,
) -> Result<models::Model, Response> {
    let user = fetch_user_or_404(db, uuid).await?;

    let stored_key =
        crypto::decrypt_aes_key_at_rest(&user.aes_key, master_key)
            .ok_or_else(|| error_response(500, "crypto_error", "Failed to decrypt AES key"))?;

    let fail_msg = if debug_mode {
        "AES key does not match".to_string()
    } else {
        "Authentication failed".to_string()
    };

    let Ok(supplied_key) = hex::decode(supplied_key_hex) else {
        return Err(error_response(400, "auth_failed", &fail_msg));
    };

    if !crypto::constant_time_eq_bytes(&stored_key, &supplied_key) {
        return Err(error_response(403, "auth_failed", &fail_msg));
    }

    Ok(user)
}