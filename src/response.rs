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