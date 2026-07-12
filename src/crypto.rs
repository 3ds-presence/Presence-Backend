use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};
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
    use rand::RngCore;
    let mut key = [0u8; AES_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random nonce (u64) using OS entropy.
pub fn generate_nonce() -> u64 {
    use rand::Rng;
    rand::rngs::OsRng.gen()
}

/// Decrypt a single block (16 bytes) with AES-256-CBC, IV=0.
///
/// Used for login verify: client encrypts nonce+padding, server decrypts.
///
/// Returns the unpadded plaintext (should be 8 bytes for the nonce).
pub fn decrypt_block(ciphertext: &[u8; 16], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let iv = [0u8; 16];
    let mut buf = *ciphertext;

    let pt = Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| CryptoError::PaddingInvalid)?;

    Ok(pt.to_vec())
}

/// Decrypt and verify a padded plaintext with AES-256-CBC, IV=0.
///
/// Used for activity auth verification. The ciphertext must be a multiple of 16 bytes.
/// Returns the unpadded plaintext.
pub fn decrypt_padded(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let iv = [0u8; 16];
    let mut buf = ciphertext.to_vec();

    let pt = Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| CryptoError::PaddingInvalid)?;

    Ok(pt.to_vec())
}

/// Calculate SHA-256 of concatenated fields in a fixed order.
///
/// Fields are concatenated as raw UTF-8 bytes without delimiters.
/// Empty fields are skipped.
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

/// Verify the auth token for an activity request.
///
/// Parameters:
/// - `auth_hex`: hex-encoded AES-256-CBC ciphertext (48 bytes = 96 hex chars)
/// - `counter`: the claimed counter value (must be > last_counter for replay protection)
/// - `fields`: the activity fields (state, details, activity_type as strings)
/// - `key`: the user's AES-256 key
///
/// Returns the counter on success.
pub fn verify_activity_auth(
    auth_hex: &str,
    counter: u64,
    fields: &[&str],
    key: &[u8; 32],
) -> Result<u64, CryptoError> {
    // Decode hex
    let ciphertext = hex::decode(auth_hex)
        .map_err(|_| CryptoError::InvalidHex)?;

    if ciphertext.len() != 48 {
        return Err(CryptoError::WrongInputSize);
    }

    // Decrypt
    let plaintext = decrypt_padded(&ciphertext, key)?;

    // Expected: counter (8 bytes) || hash (32 bytes) = 40 bytes + 8 padding = 48
    if plaintext.len() != 40 {
        return Err(CryptoError::PaddingInvalid);
    }

    // Extract counter
    let extracted_counter = u64_from_be_bytes(&plaintext[..8]);
    if extracted_counter != counter {
        return Err(CryptoError::IntegrityMismatch);
    }

    // Verify hash
    let expected_hash = sha256_fields(fields);
    let actual_hash = &plaintext[8..40];
    if actual_hash != expected_hash {
        return Err(CryptoError::IntegrityMismatch);
    }

    Ok(counter)
}

/// Get the current Unix timestamp in seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}