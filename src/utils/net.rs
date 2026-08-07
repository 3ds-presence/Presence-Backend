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

use axum::http::HeaderMap;

/// Extract the client IP from the reverse-proxy headers set by Nginx.
/// Trusts `X-Real-IP` first, then the first address of `X-Forwarded-For`.
pub fn extract_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    try_x_real_ip(headers).or_else(|| try_x_forwarded_for(headers))
}

/// Try to parse the client IP from the X-Real-IP header.
fn try_x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("x-real-ip")?;
    value.to_str().ok()?.parse::<IpAddr>().ok()
}

/// Try to parse the client IP from the X-Forwarded-For header (first address).
fn try_x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("x-forwarded-for")?;
    let first = value.to_str().ok()?.split(',').next()?.trim();
    first.parse::<IpAddr>().ok()
}