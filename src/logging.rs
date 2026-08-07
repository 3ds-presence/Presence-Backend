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

use std::fmt::Write as _;
use std::io::{Result, Write};

use chrono::Utc;
use env_logger::fmt::Formatter;
use log::Record;

/// Per-request context attached to every log line emitted while a request is
/// being handled. Populated by the request-logger middleware so that all logs
/// (including session/auth failures) carry the same `req_id`, `ip` and `path`
/// for forensic correlation — without each caller needing to pass them around.
#[derive(Clone, Default)]
pub struct RequestCtx {
    pub req_id: String,
    pub ip: String,
    pub path: String,
}

tokio::task_local! {
    pub(crate) static REQUEST_CTX: RequestCtx;
}

/// Format logs as `ts=... level=... target=... [req_id=... ip=... path=...] <message>`.
///
/// Timestamp is ISO-8601 with milliseconds and UTC so a forensic timeline can
/// be reconstructed precisely.
fn format_record(f: &mut Formatter, record: &Record) -> Result<()> {
    let mut line = format!(
        "ts={} level={} target={}",
        Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        record.level(),
        record.target()
    );

    if let Ok(ctx) = REQUEST_CTX.try_with(Clone::clone) {
        if !ctx.req_id.is_empty() {
            let _ = write!(line, " req_id={}", ctx.req_id);
        }
        if !ctx.ip.is_empty() && ctx.ip != "unknown" {
            let _ = write!(line, " ip={}", ctx.ip);
        }
        if !ctx.path.is_empty() {
            let _ = write!(line, " path={}", ctx.path);
        }
    }

    writeln!(f, "{line} {}", record.args())
}

/// Initialize logging from `RUST_LOG` (defaults to `info`).
///
/// Set `RUST_LOG=debug` (or `trace`) to get per-request bodies and internal
/// detail; keep `info,<crate>=warn` in production for a clean, greppable
/// forensic trail.
pub fn init() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(format_record)
        .init();
}

/// Identity-mask a sensitive value for logs: keep only the first 4 characters.
pub fn partial(value: &str) -> String {
    let keep: String = value.chars().take(4).collect();
    format!("{keep}****")
}

/// Mask sensitive fields in a `application/x-www-form-urlencoded` request body.
///
/// Never log `auth_hex`, `cipher_hex`, `aes_key_hex`, `temp_token` or the
/// Discord OAuth `code` in clear — a full value would allow account takeover.
pub fn mask_body(raw: &str) -> String {
    const SENSITIVE: &[&str] = &["auth_hex", "cipher_hex", "aes_key_hex", "temp_token", "code"];

    raw.split('&')
        .map(|pair| {
            let Some((key, value)) = pair.split_once('=') else {
                return pair.to_string();
            };
            if SENSITIVE.contains(&key) {
                format!("{key}={}", partial(value))
            } else {
                pair.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}