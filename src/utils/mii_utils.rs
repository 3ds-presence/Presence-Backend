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


use std::fmt;

#[derive(Debug)]
pub enum MiiError {
    HexDecode(String),
    TooShort { expected: usize, actual: usize },
}

impl fmt::Display for MiiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MiiError::HexDecode(e) => write!(f, "Hex decode error: {}", e),
            MiiError::TooShort { expected, actual } => {
                write!(f, "Mii data too short: expected at least {} bytes, got {}", expected, actual)
            }
        }
    }
}

/// Extracts the Mii name from a hex-encoded Mii data buffer.
///
/// The name is stored at offset 0x1A as UTF-16LE encoded bytes,
/// max 10 characters, null-terminated (20 bytes total).
pub fn get_mii_name(hex_data: &str) -> Result<String, MiiError> {
    let bytes = hex::decode(hex_data).map_err(|e| MiiError::HexDecode(e.to_string()))?;

    if bytes.len() < 0x1A + 20 {
        return Err(MiiError::TooShort {
            expected: 0x1A + 20,
            actual: bytes.len(),
        });
    }

    let name_bytes = &bytes[0x1A..0x1A + 20];

    let mut name_utf16 = Vec::new();
    for chunk in name_bytes.chunks(2) {
        let code_unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code_unit == 0 {
            break;
        }
        name_utf16.push(code_unit);
    }

    Ok(String::from_utf16_lossy(&name_utf16))
}