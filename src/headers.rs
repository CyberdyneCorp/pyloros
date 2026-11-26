use axum::{Router, http::HeaderValue, middleware, response::Response};

const POLICIES: &[(&str, &str)] = &[
    (
        "permissions-policy",
        "geolocation=(), microphone=(), camera=()",
    ),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
];

pub fn apply(router: Router, secure_transport: bool) -> Router {
    router.layer(middleware::map_response(
        move |mut response: Response| async move {
            let headers = response.headers_mut();
            for &(name, value) in POLICIES {
                headers.insert(name, HeaderValue::from_static(value));
            }
            headers
                .entry("content-security-policy")
                .or_insert(HeaderValue::from_static(
                    "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
                ));
            if secure_transport {
                headers.insert(
                    "strict-transport-security",
                    HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
                );
            }
            response
        },
    ))
}
