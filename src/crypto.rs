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

use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Size of our AES-256 key.
pub const AES_KEY_LEN: usize = 32;

/// Size of a SHA-256 hash.
pub const SHA256_LEN: usize = 32;

/// Error type for cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    InvalidHex,
    WrongInputSize,
    PaddingInvalid,
    IntegrityMismatch,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHex => write!(f, "invalid hex string"),
            Self::WrongInputSize => write!(f, "wrong input size"),
            Self::PaddingInvalid => write!(f, "PKCS7 padding is invalid"),
            Self::IntegrityMismatch => write!(f, "integrity check failed (SHA256 mismatch)"),
        }
    }
}

/// Generate a random AES-256 key using OS entropy.
pub fn generate_aes_key() -> [u8; AES_KEY_LEN] {
    rand::rng().random()
}

/// Generate a random nonce (u64) using OS entropy.
pub fn generate_nonce() -> u64 {
    rand::rng().random()
}

/// AES-256-CBC decrypt with IV=0 and PKCS7 unpadding.
/// Used for login verify (16-byte input) and activity auth (48-byte input).
pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let iv = [0u8; 16];
    let mut buf = ciphertext.to_vec();

    let pt = Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| CryptoError::PaddingInvalid)?;

    Ok(pt.to_vec())
}

/// SHA-256 of concatenated fields (raw UTF-8, no delimiter).
pub fn sha256_fields(fields: &[&str]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    for field in fields {
        if !field.is_empty() {
            hasher.update(field.as_bytes());
        }
    }
    hasher.finalize().into()
}

/// Extract a u64 from the first 8 bytes of a slice (big-endian).
pub fn u64_from_be_bytes(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(arr)
}

/// Verify an activity auth token: decrypt AES-CBC, check counter (replay protection),
/// and verify SHA-256 of the fields matches.
/// Returns the counter on success.
pub fn verify_activity_auth(
    auth_hex: &str,
    counter: u64,
    fields: &[&str],
    key: &[u8; 32],
) -> Result<u64, CryptoError> {
    let ciphertext = hex::decode(auth_hex).map_err(|_| CryptoError::InvalidHex)?;

    if ciphertext.len() != 48 {
        return Err(CryptoError::WrongInputSize);
    }

    let plaintext = decrypt_aes_cbc(&ciphertext, key)?;

    if plaintext.len() != 40 {
        return Err(CryptoError::PaddingInvalid);
    }

    let extracted_counter = u64_from_be_bytes(&plaintext[..8]);
    if extracted_counter != counter {
        return Err(CryptoError::IntegrityMismatch);
    }

    let expected_hash = sha256_fields(fields);
    let actual_hash = &plaintext[8..40];
    if actual_hash != expected_hash {
        return Err(CryptoError::IntegrityMismatch);
    }

    Ok(counter)
}

/// URL-encode matching the 3DS client: unreserved chars kept, space → `+`, rest → `%XX`.
pub fn url_encode_3ds(s: &str) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[allow(clippy::cast_possible_wrap)]
/// Get the current Unix timestamp in seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
