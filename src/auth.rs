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

/// A validated authentication pair: UUID + hex string (auth_hex or cipher_hex).
///
/// Creating via `Auth::new` validates the UUID format.
/// Functions that need both `uuid` and `hex` should accept `&Auth`
/// to guarantee the data has already been validated.
#[derive(Debug, Clone)]
pub struct Auth {
    pub uuid: Uuid,
    pub hex: String,
}

impl Auth {
    /// Create from a pre-validated UUID and hex string (no re-parsing).
    pub fn from_uuid(uuid: Uuid, hex: String) -> Self {
        Self { uuid, hex }
    }

    /// Parse and validate raw uuid/hex strings. Returns 400 if UUID is invalid.
    pub fn new(uuid_str: &str, hex: &str) -> Result<Self, AppError> {
        if uuid_str.is_empty() || hex.is_empty() {
            return Err(AppError(Box::new(error_response(400, "missing_field", "uuid and hex are required"))));
        }

        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| AppError(Box::new(error_response(400, "invalid_uuid", "Invalid UUID format"))))?;

        Ok(Self {
            uuid,
            hex: hex.to_string(),
        })
    }

    /// Convenience: borrow the hex string.
    pub fn hex(&self) -> &str {
        &self.hex
    }
}