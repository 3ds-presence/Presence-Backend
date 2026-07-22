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


use axum::response::Response;

/// Build a 200 success response with form-urlencoded body.
pub fn success_response(body: impl Into<String>) -> Response {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into().into())
        .unwrap()
}

/// Build an error response with form-urlencoded body.
pub fn error_response(status: u16, code: &str, message: &str) -> Response {
    let body = format!("error={}&message={}", code, urlencoding::encode(message));
    Response::builder()
        .status(status)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap()
}