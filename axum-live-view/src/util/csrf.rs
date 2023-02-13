use axum::{
    http::{
        header::{HeaderMap, COOKIE, SET_COOKIE},
        StatusCode, Uri,
    },
    response::{IntoResponse, Response},
};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

/// CSRF cookie name
const COOKIE_NAME: &str = "_lv_csrf=";
/// CSRF query name
const URI_NAME: &str = "csrf=";

/// Sets a cookie with a random CSRF token
pub(crate) fn set_cookie(headers: &mut HeaderMap) {
    let token = random_token();
    // SameSite=Lax means that the cookie is not sent on cross-site requests,
    // such as on requests to load images or frames, but is sent when a user
    // is navigating to the origin site from an external site (for example,
    // when following a link). This is the default behavior if the SameSite
    // attribute is not specified.
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
    if let Ok(val) = format!("{COOKIE_NAME}{token}; SameSite=Lax").parse() {
        headers.insert(SET_COOKIE, val);
    }
}

/// Retrieves CSRF token from cookies
pub(crate) fn token_from_cookies(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split_once(COOKIE_NAME))
        .and_then(|(_, s)| s.split(";").next())
}

/// Retrieves CSRF token from URI
pub(crate) fn token_from_uri(uri: &Uri) -> Option<&str> {
    uri.query()
        .and_then(|s| s.split_once(URI_NAME))
        .and_then(|(_, s)| s.split("&").next())
}

/// Handshake rejection
pub(crate) fn rejection(reason: &'static str) -> Response {
    (StatusCode::FORBIDDEN, reason).into_response()
}

fn random_token() -> u64 {
    RandomState::new().build_hasher().finish()
}
