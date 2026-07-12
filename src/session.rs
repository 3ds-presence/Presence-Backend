use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use discord_social_rpc::{DiscordRpcClient, DiscordSocialRpc};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::crypto;

/// Timeout for pending verification sessions (seconds).
const PENDING_TIMEOUT_SECS: u64 = 30;

/// State of a session during the login flow.
pub enum SessionState {
    /// Waiting for the client to prove they have the AES key.
    PendingVerify {
        nonce: u64,
        aes_key: [u8; 32],
        created_at: Instant,
        client_ip: IpAddr,
    },
    /// Session is active — DiscordRpcClient is connected and running.
    Active {
        client: Arc<DiscordRpcClient>,
        aes_key: [u8; 32],
        last_counter: AtomicU64,
        last_activity: Instant,
        client_ip: IpAddr,
    },
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingVerify { nonce, .. } => {
                f.debug_struct("PendingVerify").field("nonce", nonce).finish()
            }
            Self::Active { last_activity, .. } => {
                f.debug_struct("Active")
                    .field("last_activity", last_activity)
                    .finish()
            }
        }
    }
}

/// Custom session error type.
#[derive(Debug)]
pub enum SessionError {
    Message(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<&str> for SessionError {
    fn from(s: &str) -> Self {
        SessionError::Message(s.to_string())
    }
}

impl From<String> for SessionError {
    fn from(s: String) -> Self {
        SessionError::Message(s)
    }
}

/// Manages all active sessions (both pending and active).
pub struct SessionManager {
    sessions: Mutex<HashMap<Uuid, SessionState>>,
    ip_counts: Mutex<HashMap<IpAddr, usize>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ip_counts: Mutex::new(HashMap::new()),
        }
    }

    /// Decrement the IP counter for a given address.
    fn decrement_ip(ip_counts: &mut HashMap<IpAddr, usize>, ip: IpAddr) {
        match ip_counts.get_mut(&ip) {
            Some(count) if *count > 1 => *count -= 1,
            _ => {
                ip_counts.remove(&ip);
            }
        }
    }

    /// Extract the client IP from a session state (if present) and decrement the counter.
    async fn remove_session_with_ip(&self, uuid: &Uuid) -> Option<SessionState> {
        let mut sessions = self.sessions.lock().await;
        let mut ip_counts = self.ip_counts.lock().await;

        let state = sessions.remove(uuid);
        if let Some(ref s) = state {
            let ip = s.client_ip();
            Self::decrement_ip(&mut ip_counts, ip);
        }
        state
    }

    /// Create a new pending session with a nonce challenge.
    pub async fn create_pending(
        &self,
        uuid: Uuid,
        aes_key: [u8; 32],
        client_ip: IpAddr,
        max_per_ip: usize,
    ) -> Result<u64, &'static str> {
        let nonce = crypto::generate_nonce();
        let mut sessions = self.sessions.lock().await;
        let mut ip_counts = self.ip_counts.lock().await;

        let count = ip_counts.entry(client_ip).or_insert(0);
        if *count >= max_per_ip {
            return Err("too many sessions from this IP");
        }
        *count += 1;

        sessions.insert(uuid, SessionState::PendingVerify {
            nonce,
            aes_key,
            created_at: Instant::now(),
            client_ip,
        });

        Ok(nonce)
    }

    /// Verify a pending session: check the encrypted nonce and promote to active.
    pub async fn verify_and_activate(
        &self,
        uuid: Uuid,
        cipher_hex: &str,
        discord_rpc: &DiscordSocialRpc,
        access_token: &str,
    ) -> Result<u64, SessionError> {
        let mut sessions = self.sessions.lock().await;

        let state = sessions.remove(&uuid)
            .ok_or_else(|| SessionError::from("no pending session for this uuid"))?;

        let (nonce, aes_key, client_ip) = match state {
            SessionState::PendingVerify { nonce, aes_key, client_ip, .. } => (nonce, aes_key, client_ip),
            SessionState::Active { .. } => {
                return Err("session is already active".into());
            }
        };

        // Decode the ciphertext (32 hex chars = 16 bytes)
        let cipher_bytes = hex::decode(cipher_hex)
            .map_err(|_| SessionError::from("invalid hex in cipher_hex"))?;
        if cipher_bytes.len() != 16 {
            return Err("cipher_hex must be 32 hex chars (16 bytes)".into());
        }
        let mut cipher_arr = [0u8; 16];
        cipher_arr.copy_from_slice(&cipher_bytes);

        // Decrypt. decrypt_block uses PKCS7 internally and returns only the
        // unpadded plaintext (8 bytes = the nonce). If padding was invalid,
        // it returns CryptoError::PaddingInvalid.
        let plaintext = crypto::decrypt_block(&cipher_arr, &aes_key)
            .map_err(|e| SessionError::from(format!("decryption failed: {}", e)))?;

        // plaintext should be exactly 8 bytes (nonce) + padding removed
        if plaintext.len() < 8 {
            return Err("decrypted data too short".into());
        }

        // Extract nonce
        let extracted_nonce = crypto::u64_from_be_bytes(&plaintext[..8]);
        if extracted_nonce != nonce {
            return Err("nonce mismatch".into());
        }

        // Create the Discord RPC client
        let client = discord_rpc.create_new_client(access_token)
            .map_err(|e| SessionError::from(format!("failed to create Discord client: {}", e)))?;

        let client = Arc::new(client);

        // Start the gateway in a blocking thread
        let client_clone = client.clone();
        tokio::task::spawn_blocking(move || {
            let _ = client_clone.start_activity();
        }).await.map_err(|e| SessionError::from(format!("spawn_blocking failed: {}", e)))?;

        log::info!("session {}: Discord client created and gateway started", uuid);

        // Store active session
        sessions.insert(uuid, SessionState::Active {
            client,
            aes_key,
            last_counter: AtomicU64::new(nonce),
            last_activity: Instant::now(),
            client_ip,
        });

        Ok(nonce)
    }

    /// Internal helper: verify that an active session's auth token and counter
    /// are valid. Takes the active state directly and returns owned data,
    /// avoiding complex lifetime issues with the sessions lock guard.
    async fn verify_active_session_inner(
        state: &mut SessionState,
        uuid: Uuid,
        counter: u64,
        auth_hex: &str,
        fields: &[&str],
        cooldown_secs: u64,
    ) -> Result<(Arc<DiscordRpcClient>, [u8; 32], u64, Instant), SessionError> {
        let (client, aes_key, last_counter, last_activity) = match state {
            SessionState::Active { client, aes_key, last_counter, last_activity, .. } => {
                (client.clone(), *aes_key, last_counter.load(Ordering::SeqCst), *last_activity)
            }
            SessionState::PendingVerify { .. } => {
                return Err("session is pending verification, not active".into());
            }
        };

        // Check cooldown
        let elapsed = last_activity.elapsed().as_secs();
        if elapsed < cooldown_secs {
            return Err(SessionError::from(format!("cooldown: wait {} seconds", cooldown_secs - elapsed)));
        }

        // Log the verification details
        let expected_hash = hex::encode(crypto::sha256_fields(fields));
        log::debug!(
            "verify: uuid={} counter={} fields={:?} auth_hex={}.. expected_hash={}",
            uuid, counter, fields,
            &auth_hex[..16], expected_hash
        );

        // Verify auth
        crypto::verify_activity_auth(auth_hex, counter, fields, &aes_key)
            .map_err(|e| SessionError::from(format!("auth verification failed: {}", e)))?;

        // Check counter monotonic
        if counter <= last_counter {
            return Err(SessionError::from(format!("replay detected: counter {} <= last {}", counter, last_counter)));
        }

        Ok((client, aes_key, last_counter, last_activity))
    }

    /// Update activity for an active session.
    pub async fn update_activity(
        &self,
        uuid: Uuid,
        counter: u64,
        auth_hex: &str,
        state: Option<&str>,
        details: Option<&str>,
        activity_type: Option<u8>,
        cooldown_secs: u64,
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().await;

        let session = sessions.get_mut(&uuid)
            .ok_or_else(|| SessionError::from("session not found"))?;

        // Build the fields slice for SHA256
        let state_str = state.unwrap_or("");
        let details_str = details.unwrap_or("");
        let activity_type_str = &activity_type.map(|t| t.to_string()).unwrap_or_default();
        let fields = [state_str, details_str, activity_type_str];

        // Verify the session is active and auth is valid
        let (client, _aes_key, _, _) =
            Self::verify_active_session_inner(session, uuid, counter, auth_hex, &fields, cooldown_secs).await?;

        // Build the Activity and send it via spawn_blocking
        let mut activity = discord_social_rpc::Activity::new();
        if let Some(s) = state {
            if !s.is_empty() {
                activity = activity.state(s);
            }
        }
        if let Some(d) = details {
            if !d.is_empty() {
                activity = activity.details(d);
            }
        }
        if let Some(t) = activity_type {
            let at = match t {
                2 => discord_social_rpc::ActivityType::Listening,
                3 => discord_social_rpc::ActivityType::Watching,
                5 => discord_social_rpc::ActivityType::Competing,
                _ => discord_social_rpc::ActivityType::Playing,
            };
            activity = activity.activity_type(at);
        }

        let client_set = client.clone();
        tokio::task::spawn_blocking(move || {
            let _ = client_set.set_activity(activity);
        }).await.map_err(|e| SessionError::from(format!("set_activity spawn failed: {}", e)))?;

        // Update state
        if let SessionState::Active { last_counter, last_activity, .. } = session {
            last_counter.store(counter, Ordering::SeqCst);
            *last_activity = Instant::now();
        }

        Ok(())
    }

    /// Stop the Discord activity for an active session and remove the session.
    pub async fn stop_activity(
        &self,
        uuid: Uuid,
        counter: u64,
        auth_hex: &str,
        cooldown_secs: u64,
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().await;

        let session = sessions.get_mut(&uuid)
            .ok_or_else(|| SessionError::from("session not found"))?;

        // Fields for logout: use ["logout","",""] as the auth payload
        let fields = ["logout", "", ""];

        // Verify the session is active and auth is valid
        let (client, _aes_key, _, _) =
            Self::verify_active_session_inner(session, uuid, counter, auth_hex, &fields, cooldown_secs).await?;

        // Stop the activity
        let client_stop = client.clone();
        tokio::task::spawn_blocking(move || {
            let _ = client_stop.stop_activity();
        }).await.map_err(|e| SessionError::from(format!("stop_activity spawn failed: {}", e)))?;

        // Remove the session and decrement IP count
        let ip = session.client_ip();
        sessions.remove(&uuid);
        let mut ip_counts = self.ip_counts.lock().await;
        Self::decrement_ip(&mut ip_counts, ip);
        log::info!("session {}: activity stopped by client (logout)", uuid);

        Ok(())
    }

    /// Get UUIDs of sessions that have exceeded the timeout.
    pub async fn get_expired_active_sessions(&self, timeout_secs: u64) -> Vec<Uuid> {
        let sessions = self.sessions.lock().await;
        sessions.iter()
            .filter_map(|(uuid, state)| {
                match state {
                    SessionState::Active { last_activity, .. } => {
                        if last_activity.elapsed().as_secs() > timeout_secs {
                            Some(*uuid)
                        } else {
                            None
                        }
                    }
                    SessionState::PendingVerify { created_at, .. } => {
                        if created_at.elapsed().as_secs() > PENDING_TIMEOUT_SECS {
                            Some(*uuid)
                        } else {
                            None
                        }
                    }
                }
            })
            .collect()
    }

    /// Remove a session by UUID, decrement IP counter, and return its state.
    pub async fn remove_session(&self, uuid: &Uuid) -> Option<SessionState> {
        self.remove_session_with_ip(uuid).await
    }

    /// Check if a session exists and is active.
    pub async fn is_active(&self, uuid: &Uuid) -> bool {
        let sessions = self.sessions.lock().await;
        matches!(sessions.get(uuid), Some(SessionState::Active { .. }))
    }

    /// Get a copy of the DiscordRpcClient for an active session.
    pub async fn get_client(&self, uuid: &Uuid) -> Option<Arc<DiscordRpcClient>> {
        let sessions = self.sessions.lock().await;
        match sessions.get(uuid) {
            Some(SessionState::Active { client, .. }) => Some(client.clone()),
            _ => None,
        }
    }
}

/// Helper to extract the client IP from any session state variant.
impl SessionState {
    pub fn client_ip(&self) -> IpAddr {
        match self {
            SessionState::PendingVerify { client_ip, .. } => *client_ip,
            SessionState::Active { client_ip, .. } => *client_ip,
        }
    }
}