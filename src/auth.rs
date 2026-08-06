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

use crate::response::AppError;
use crate::validation;

/// A validated authentication pair: UUID + hex string (`auth_hex` or `cipher_hex`).
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
    pub const fn from_uuid(uuid: Uuid, hex: String) -> Self {
        Self { uuid, hex }
    }

    /// Parse and validate raw uuid/hex strings. Returns 400 if UUID is invalid.
    pub fn new(uuid_str: &str, hex: &str) -> Result<Self, AppError> {
        let uuid = validation::validate_uuid(uuid_str)?;
        let hex = validation::validate_auth_hex(hex)?.to_string();

        Ok(Self { uuid, hex })
    }

    /// Convenience: borrow the hex string.
    pub fn hex(&self) -> &str {
        &self.hex
    }
}
