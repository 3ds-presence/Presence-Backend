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