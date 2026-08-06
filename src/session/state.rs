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

use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use discord_social_rpc::DiscordRpcClient;
use uuid::Uuid;

use activity_generator::UserInfo;

/// State of a session during the login flow.
pub enum SessionState {
    /// Waiting for the client to prove they have the AES key.
    PendingVerify {
        nonce: u64,
        aes_key: [u8; 32],
        created_at: Instant,
        client_ip: IpAddr,
    },
    /// Waiting for the user to accept the privacy policy (RGPD consent).
    PendingConsent {
        discord_id: String,
        access_token: String,
        refresh_token: String,
        token_expires_at: i64,
        temp_token: Uuid,
        created_at: Instant,
    },
    /// Session is active — `DiscordRpcClient` is connected and running.
    Active {
        client: Arc<DiscordRpcClient>,
        aes_key: [u8; 32],
        last_counter: AtomicU64,
        last_activity: Instant,
        client_ip: IpAddr,
        user_info: Option<UserInfo>,
    },
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingVerify { nonce, .. } => f
                .debug_struct("PendingVerify")
                .field("nonce", nonce)
                .finish(),
            Self::PendingConsent {
                temp_token,
                created_at,
                ..
            } => f
                .debug_struct("PendingConsent")
                .field("temp_token", temp_token)
                .field("created_at", created_at)
                .finish(),
            Self::Active {
                last_activity,
                user_info,
                ..
            } => f
                .debug_struct("Active")
                .field("last_activity", last_activity)
                .field("user_info", user_info)
                .finish(),
        }
    }
}

impl SessionState {
    pub const fn client_ip(&self) -> IpAddr {
        match self {
            Self::PendingVerify { client_ip, .. } | Self::Active { client_ip, .. } => *client_ip,
            Self::PendingConsent { .. } => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        }
    }
}