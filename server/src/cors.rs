//! Cross-origin access in two tiers (security audit D, "permissive CORS with
//! credentials").
//!
//! Atomic is a headless CMS: a page on any web origin may read public data
//! from it, so every origin gets `Access-Control-Allow-Origin`, any method and
//! any header. What used to come with that was `Access-Control-Allow-Credentials`
//! for every origin too, which tells the browser it may attach the
//! `atomic_session` cookie to a request made by any site. The cookie's own
//! `SameSite=Lax` was the only thing preventing that.
//!
//! The clients that need credentials are all on origins this server answers
//! for: the data-browser served by the server itself, a tenant on a subdomain
//! of the base domain, the Vite dev server on another loopback port, and the
//! desktop and Android webviews (`tauri://localhost` on macOS and iOS,
//! `http://tauri.localhost` on Windows and Android), which talk to a server
//! bound to loopback. So credentials are allowed for exactly those, by the
//! same rule `RequestContext` uses to decide which `Host` to trust, and every
//! other origin keeps its any-origin access without them.

use actix_cors::Cors;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web, Error,
};

use crate::{appstate::AppState, config::Opts};

/// The CORS layer: any origin, any method, any header, credentials. It is
/// wrapped by [`credentials_gate`], which takes the credentials back for
/// origins that are not this server's own.
///
/// "Any header" includes `x-atomic-signature-version`, the version 2 request
/// signature header (ontola/atomic-plugins#54): `Cors::permissive` echoes
/// whatever a preflight asks for. If this ever becomes an allowlist, that
/// header has to be on it; `the_v2_signature_header_passes_a_preflight`
/// guards it.
pub(crate) fn any_origin() -> Cors {
    Cors::permissive().expose_headers([
        crate::serve::SERVER_VERSION_HEADER,
        crate::write_load::PACE_HEADER,
        crate::write_load::RETRY_AFTER_MS_HEADER,
        "Retry-After",
    ])
}

/// Whether a browser on `origin` (the `Origin` header, `scheme://host[:port]`)
/// may send the session cookie along: the configured domain, a subdomain of
/// the multi-tenant base domain, loopback (which covers `tauri.localhost`), or
/// the desktop webview's own `tauri://localhost` scheme. `mapped` says
/// whether this server has a Drive mapping for a host (a vanity name outside
/// every configured suffix).
pub(crate) fn origin_may_send_credentials(
    origin: &str,
    opts: &Opts,
    mapped: impl Fn(&str) -> bool,
) -> bool {
    let Some((scheme, host)) = origin.split_once("://") else {
        // `null` (a sandboxed frame, a `file:` page) and anything else that
        // is not an origin with a host.
        return false;
    };
    if host.is_empty() || host.contains('/') {
        return false;
    }
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "https" => {
            crate::context::host_is_served_here(host, opts)
                || mapped(crate::context::strip_port(host))
        }
        "tauri" => host.eq_ignore_ascii_case("localhost"),
        _ => false,
    }
}

/// Removes `Access-Control-Allow-Credentials` from the response unless the
/// request's `Origin` is one this server answers for. Register it outside
/// the CORS layer (`.wrap(cors).wrap(from_fn(credentials_gate))`) so it sees
/// the headers that layer added, on preflight answers and on real responses
/// alike. A request without an `Origin` is not a cross-origin request, so
/// the header (which `actix-cors` adds regardless) grants nothing there and
/// is removed too.
pub(crate) async fn credentials_gate(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let trusted = match (
        req.headers().get(header::ORIGIN).map(|o| o.to_str()),
        req.app_data::<web::Data<AppState>>(),
    ) {
        (Some(Ok(origin)), Some(appstate)) => {
            origin_may_send_credentials(origin, &appstate.config.opts, |host| {
                appstate.store.has_drive_mapping(host)
            })
        }
        // Fail closed: no origin, an origin that is not even a string, or no
        // policy to consult, gets no credentials.
        _ => false,
    };
    let mut res = next.call(req).await?;
    if !trusted {
        res.headers_mut()
            .remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    // `actix_web::test` under its own name would shadow the `#[test]`
    // attribute for the unit tests below.
    use actix_web::{
        http::{Method, StatusCode},
        middleware, test as actix_test, App, HttpResponse,
    };
    use clap::Parser;

    fn opts(domain: &str, base: Option<&str>) -> Opts {
        let mut args = vec!["atomic-server", "--domain", domain];
        if let Some(b) = base {
            args.push("--base-domain");
            args.push(b);
        }
        Opts::parse_from(args)
    }

    #[test]
    fn own_origins_may_send_credentials() {
        let o = opts("atomicdata.dev", Some("atomicserver.eu"));
        for origin in [
            "https://atomicdata.dev",
            "https://AtomicData.dev:443",
            "https://joep.atomicserver.eu",
            "http://localhost:6747",
            "http://127.0.0.1:9883",
            "http://[::1]:9883",
            "http://atomic.localhost:9883",
            "tauri://localhost",
            "http://tauri.localhost",
        ] {
            assert!(
                origin_may_send_credentials(origin, &o, |_| false),
                "{origin}"
            );
        }
    }

    #[test]
    fn foreign_origins_may_not() {
        let o = opts("atomicdata.dev", Some("atomicserver.eu"));
        for origin in [
            "https://evil.example",
            "https://atomicdata.dev.evil.example",
            "https://notatomicserver.eu",
            "null",
            "",
            "atomicdata.dev",
            "https://atomicdata.dev/path",
            "tauri://evil.example",
            "chrome-extension://abcdefghijklmnop",
            "ftp://atomicdata.dev",
        ] {
            assert!(
                !origin_may_send_credentials(origin, &o, |_| false),
                "{origin:?}"
            );
        }
    }

    /// A vanity host outside every configured suffix gets credentials once
    /// this server has a Drive mapping for it, and only then.
    #[test]
    fn mapped_vanity_hosts_may_send_credentials() {
        let o = opts("node1.atomicserver.eu", Some("atomicserver.eu"));
        let mapped = |host: &str| host == "ontola.atomic.place";
        assert!(!origin_may_send_credentials(
            "https://ontola.atomic.place",
            &o,
            |_| false
        ));
        assert!(origin_may_send_credentials(
            "https://ontola.atomic.place",
            &o,
            mapped
        ));
        assert!(origin_may_send_credentials(
            "https://ontola.atomic.place:443",
            &o,
            mapped
        ));
        assert!(!origin_may_send_credentials(
            "https://evil.atomic.place",
            &o,
            mapped
        ));
    }

    /// The full stack as `serve.rs` registers it: permissive CORS with the
    /// credentials gate outside it, against a server configured for
    /// `atomicdata.dev`. A foreign origin gets any-origin access without
    /// credentials, an own origin gets both, on preflight and on a real
    /// request.
    #[actix_rt::test]
    async fn foreign_origin_reads_without_credentials_own_origin_with() {
        let appstate = crate::tests::init_test_appstate(&[
            "--domain",
            "atomicdata.dev",
            "--base-domain",
            "atomicdata.dev",
        ])
        .await;
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(appstate))
                .wrap(any_origin())
                .wrap(middleware::from_fn(credentials_gate))
                .route(
                    "/ping",
                    web::get().to(|| async { HttpResponse::Ok().body("pong") }),
                ),
        )
        .await;

        let foreign = "https://evil.example";
        let own = "https://atomicdata.dev";
        let tenant = "https://joep.atomicdata.dev";
        let desktop = "tauri://localhost";

        // Real requests.
        for (origin, credentials) in [
            (foreign, false),
            (own, true),
            (tenant, true),
            (desktop, true),
        ] {
            let req = actix_test::TestRequest::get()
                .uri("/ping")
                .insert_header((header::ORIGIN, origin))
                .to_request();
            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{origin}");
            let headers = resp.headers();
            assert_eq!(
                headers
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|v| v.to_str().ok()),
                Some(origin),
                "{origin}: any origin may read"
            );
            assert_eq!(
                headers
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .and_then(|v| v.to_str().ok()),
                credentials.then_some("true"),
                "{origin}: credentials only for our own origins"
            );
            assert!(
                headers
                    .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.split(',').any(|h| h
                        .trim()
                        .eq_ignore_ascii_case(crate::serve::SERVER_VERSION_HEADER))),
                "{origin}: the version header stays exposed"
            );
            // A cross-origin client reads the load signal from these.
            for exposed in [
                crate::write_load::PACE_HEADER,
                crate::write_load::RETRY_AFTER_MS_HEADER,
                "Retry-After",
            ] {
                assert!(
                    headers
                        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v
                            .split(',')
                            .any(|h| h.trim().eq_ignore_ascii_case(exposed))),
                    "{origin}: {exposed} stays exposed"
                );
            }
        }

        // Preflights.
        for (origin, credentials) in [(foreign, false), (own, true)] {
            let req = actix_test::TestRequest::default()
                .method(Method::OPTIONS)
                .uri("/ping")
                .insert_header((header::ORIGIN, origin))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .insert_header((
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "content-type, x-atomic-signature",
                ))
                .to_request();
            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{origin}: preflight passes");
            let headers = resp.headers();
            assert_eq!(
                headers
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|v| v.to_str().ok()),
                Some(origin),
                "{origin}"
            );
            assert!(
                headers
                    .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                    .is_some_and(|v| v.to_str().unwrap_or_default().contains("POST")),
                "{origin}: POST is allowed"
            );
            assert!(
                headers
                    .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                    .is_some_and(|v| v
                        .to_str()
                        .unwrap_or_default()
                        .contains("x-atomic-signature")),
                "{origin}: the signing headers are allowed"
            );
            assert_eq!(
                headers
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .and_then(|v| v.to_str().ok()),
                credentials.then_some("true"),
                "{origin}: credentials only for our own origins"
            );
        }

        // Not a cross-origin request: nothing to grant.
        let req = actix_test::TestRequest::get().uri("/ping").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none());
    }

    /// A browser sending a version 2 request signature names
    /// `x-atomic-signature-version` in its preflight, from our own origin and
    /// from a foreign or null-origin frame alike.
    #[actix_rt::test]
    async fn the_v2_signature_header_passes_a_preflight() {
        let appstate = crate::tests::init_test_appstate(&["--domain", "atomicdata.dev"]).await;
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(appstate))
                .wrap(any_origin())
                .wrap(middleware::from_fn(credentials_gate))
                .route(
                    "/ping",
                    web::post().to(|| async { HttpResponse::Ok().body("pong") }),
                ),
        )
        .await;
        let requested = "content-type, x-atomic-agent, x-atomic-public-key, x-atomic-signature, x-atomic-timestamp, x-atomic-signature-version";
        for origin in ["https://atomicdata.dev", "https://evil.example", "null"] {
            let req = actix_test::TestRequest::default()
                .method(Method::OPTIONS)
                .uri("/ping")
                .insert_header((header::ORIGIN, origin))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, requested))
                .to_request();
            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{origin}");
            let allowed = resp
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_ascii_lowercase();
            assert!(
                allowed.contains("x-atomic-signature-version"),
                "{origin}: {allowed}"
            );
        }
    }
}
