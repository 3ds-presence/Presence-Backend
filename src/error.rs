use axum::response::Response;

/// Build an error response with form-urlencoded body.
pub fn error_response(status: u16, code: &str, message: &str) -> Response {
    let encoded = message.replace(' ', "+");
    let body = format!("error={}&message={}", code, encoded);
    Response::builder()
        .status(status)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap()
}