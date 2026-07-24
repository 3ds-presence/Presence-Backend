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

use uuid::Uuid;

use crate::response::{error_response, AppError};

/// Max length of a UUID string (36 chars).
pub const UUID_MAX_LEN: usize = 36;

/// Expected length of auth_hex: 48 bytes → 96 hex chars.
pub const AUTH_HEX_LEN: usize = 96;

/// Expected length of cipher_hex: 16 bytes → 32 hex chars.
pub const CIPHER_HEX_LEN: usize = 32;

/// Expected length of AES key hex: 32 bytes → 64 hex chars.
pub const AES_KEY_HEX_LEN: usize = 64;

/// Expected length of a title ID: 16 hex chars.
pub const TITLEID_LEN: usize = 16;

/// Max length of a game name (512 chars).
pub const NAME_MAX_LEN: usize = 512;

/// Max length of a publisher name (256 chars).
pub const PUBLISHER_MAX_LEN: usize = 256;

/// Max length of extra info (1024 chars).
pub const EXTRA_MAX_LEN: usize = 1024;

/// Max length of a Mii hex string (192 chars).
pub const MII_MAX_LEN: usize = 192;

/// Max length of a Discord OAuth2 code.
pub const CODE_MAX_LEN: usize = 128;

/// Check a hex string is exactly `expected_len` chars and valid hex.
fn check_hex_exact(value: &str, expected_len: usize, field_name: &str) -> Result<(), AppError> {
    if value.len() != expected_len {
        return Err(AppError(Box::new(error_response(
            400,
            &format!("invalid_{}", field_name),
            &format!(
                "{} must be exactly {} hex characters",
                field_name, expected_len
            ),
        ))));
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError(Box::new(error_response(
            400,
            &format!("invalid_{}", field_name),
            &format!("{} must contain only hex characters", field_name),
        ))));
    }
    Ok(())
}

/// Check that a string is not empty and does not exceed `max_len`.
fn check_max_len(value: &str, max_len: usize, field_name: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(AppError(Box::new(error_response(
            400,
            &format!("missing_{}", field_name),
            &format!("{} is required", field_name),
        ))));
    }
    if value.len() > max_len {
        return Err(AppError(Box::new(error_response(
            400,
            &format!("invalid_{}", field_name),
            &format!("{} too long (max {} characters)", field_name, max_len),
        ))));
    }
    Ok(())
}

/// Validate a UUID string (max 36 chars) and return the parsed `Uuid`.
pub fn validate_uuid(uuid: &str) -> Result<Uuid, AppError> {
    check_max_len(uuid, UUID_MAX_LEN, "uuid")?;
    Uuid::parse_str(uuid).map_err(|_| {
        AppError(Box::new(error_response(
            400,
            "invalid_uuid",
            "Invalid UUID format",
        )))
    })
}

/// Validate an auth_hex string (exactly 96 hex chars) and return it.
pub fn validate_auth_hex(hex: &str) -> Result<&str, AppError> {
    check_hex_exact(hex, AUTH_HEX_LEN, "auth_hex")?;
    Ok(hex)
}

/// Validate a cipher_hex string (exactly 32 hex chars) and return it.
pub fn validate_cipher_hex(hex: &str) -> Result<&str, AppError> {
    check_hex_exact(hex, CIPHER_HEX_LEN, "cipher_hex")?;
    Ok(hex)
}

/// Validate an AES key hex string (exactly 64 hex chars) and return it.
pub fn validate_aes_key_hex(hex: &str) -> Result<&str, AppError> {
    check_hex_exact(hex, AES_KEY_HEX_LEN, "aes_key_hex")?;
    Ok(hex)
}

/// Validate a title ID (exactly 16 hex chars) and return it.
pub fn validate_titleid(titleid: Option<String>) -> Result<String, AppError> {
    let t = titleid.ok_or_else(|| {
        AppError(Box::new(error_response(
            400,
            "missing_field",
            "titleid is required",
        )))
    })?;
    check_hex_exact(&t, TITLEID_LEN, "titleid")?;
    Ok(t)
}

/// Validate a game name (max 512 chars, non-empty) and return it.
pub fn validate_name(name: Option<String>) -> Result<String, AppError> {
    let n = name.ok_or_else(|| {
        AppError(Box::new(error_response(
            400,
            "missing_field",
            "name is required",
        )))
    })?;
    check_max_len(&n, NAME_MAX_LEN, "name")?;
    Ok(n)
}

/// Validate a publisher name (max 256 chars, non-empty) and return it.
pub fn validate_publisher(publisher: Option<String>) -> Result<String, AppError> {
    let p = publisher.ok_or_else(|| {
        AppError(Box::new(error_response(
            400,
            "missing_field",
            "publisher is required",
        )))
    })?;
    check_max_len(&p, PUBLISHER_MAX_LEN, "publisher")?;
    Ok(p)
}

/// Validate extra data (max 1024 chars, optional) and return it.
pub fn validate_extra(extra: Option<String>) -> Result<Option<String>, AppError> {
    if let Some(ref e) = extra {
        if e.len() > EXTRA_MAX_LEN {
            return Err(AppError(Box::new(error_response(
                400,
                "invalid_extra",
                &format!("extra too long (max {} characters)", EXTRA_MAX_LEN),
            ))));
        }
    }
    Ok(extra)
}

/// Validate a Mii hex string (max 192 hex chars, optional) and return it.
pub fn validate_mii(mii: Option<String>) -> Result<Option<String>, AppError> {
    if let Some(ref m) = mii {
        if m.len() > MII_MAX_LEN {
            return Err(AppError(Box::new(error_response(
                400,
                "invalid_mii",
                &format!("mii too long (max {} characters)", MII_MAX_LEN),
            ))));
        }
        if !m.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError(Box::new(error_response(
                400,
                "invalid_mii",
                "mii must contain only hex characters",
            ))));
        }
    }
    Ok(mii)
}

/// Validate a Discord OAuth2 code (max 128 chars, non-empty) and return it.
pub fn validate_code(code: &str) -> Result<&str, AppError> {
    check_max_len(code, CODE_MAX_LEN, "code")?;
    Ok(code)
}
