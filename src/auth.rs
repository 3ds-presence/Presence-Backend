use uuid::Uuid;

use crate::response::error_response;

/// A validated authentication pair: UUID + hex string (auth_hex or cipher_hex).
///
/// Creating an `Auth` via `Auth::new(...)` validates that the UUID is well-formed.
/// All functions that need both `uuid` and `auth_hex`/`cipher_hex` should accept `&Auth`
/// to guarantee the data has already been validated.
#[derive(Debug, Clone)]
pub struct Auth {
    pub uuid: Uuid,
    pub hex: String,
}

impl Auth {
    /// Create a new `Auth` from raw uuid and hex strings.
    ///
    /// Returns an error response (400) if the UUID is not valid.
    pub fn new(uuid_str: &str, hex: &str) -> Result<Self, axum::response::Response> {
        if uuid_str.is_empty() || hex.is_empty() {
            return Err(error_response(400, "missing_field", "uuid and hex are required"));
        }

        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| error_response(400, "invalid_uuid", "Invalid UUID format"))?;

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