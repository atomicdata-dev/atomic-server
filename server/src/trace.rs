/// Whether `sentry_actix` already reports the failures logged under this
/// tracing target, so the Sentry tracing layer must not report them again.
///
/// `tracing_actix_web` logs every failed request (its `emit_event_on_error`
/// feature, on by default) and `sentry_actix` captures the same 5xx failures
/// with the request attached. Only the latter should reach Sentry.
fn reported_by_sentry_actix(target: &str) -> bool {
    target.starts_with("tracing_actix_web")
}

/// Whether a Sentry event describes a host we proxy for being down. That is
/// the other host's outage, not a fault of this node, and a page that lists
/// many of its resources (the sync page) would file one event per resource.
fn is_upstream_unreachable(event: &sentry::protocol::Event<'_>) -> bool {
    let marker = atomic_lib::errors::UPSTREAM_UNREACHABLE_MARKER;
    event.message.as_deref().is_some_and(|m| m.contains(marker))
        || event
            .exception
            .iter()
            .any(|e| e.value.as_deref().is_some_and(|v| v.contains(marker)))
}

/// Start logging / tracing. Creates a subscribers that logs to stdout.
/// Also optionally creates a Chrome trace file. Starts OpenTelemetry if configured.
/// Returns a [tracing_chrome::FlushGuard] that should be dropped when the server is no longer needed.
pub fn init_tracing(config: &crate::config::Config) -> Option<tracing_chrome::FlushGuard> {
    // Enable logging, but keep chatty crates quiet.
    let log_level = match config.opts.log_level {
        crate::config::LogLevel::Warn => "warn",
        crate::config::LogLevel::Info => "info",
        crate::config::LogLevel::Debug => "debug",
        crate::config::LogLevel::Trace => "trace",
    };
    // Build the tracing-subscriber filter directly. Don't pollute RUST_LOG —
    // clap reads RUST_LOG into Config.log_level as a value_enum (warn/info/
    // debug/trace) and chokes on the multi-spec format below. Tests that
    // re-parse Config in the same process would fail after the first
    // init_tracing call.
    //
    // Third-party libraries kept at `warn` or higher to prevent log floods:
    // - loro_internal: every snapshot export logs per-block-section counters.
    // - pkarr / reqwest: chatty DHT/HTTP internals.
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!(
            "{log_level},loro_internal=warn,pkarr=warn,reqwest=warn"
        ))
    });
    // Sentry layer: `error!` events become Sentry issues, `warn!`/`info!`
    // become breadcrumbs attached to the next issue. A no-op when no Sentry
    // client is bound (see `init_sentry`), so it is always safe to install.
    //
    // Except for `tracing_actix_web`, which logs every failed request itself
    // ("Error encountered while processing the incoming HTTP request", at
    // `error!` for a 5xx and `warn!` for a 4xx). `sentry_actix` already
    // reports those same 5xx failures, with the request attached, so letting
    // both through files every server error in Sentry twice. It did: the
    // staging floods of September 2026 arrived as paired issue groups of
    // 6313 and 6312 events. Keep the log line, drop the second report.
    let tracing_registry = tracing_subscriber::registry().with(filter).with(
        sentry::integrations::tracing::layer().event_filter(|metadata| {
            if reported_by_sentry_actix(metadata.target()) {
                sentry::integrations::tracing::EventFilter::Ignore
            } else {
                sentry::integrations::tracing::default_event_filter(metadata)
            }
        }),
    );

    match config.opts.trace {
        crate::config::Tracing::Stdout => {
            let terminal_layer = tracing_subscriber::fmt::Layer::default();
            let _ = tracing_registry.with(terminal_layer).try_init();
        }
        crate::config::Tracing::Chrome => {
            let (chrome_layer, flush_guard) = tracing_chrome::ChromeLayerBuilder::new()
                .include_args(true)
                .build();
            // try_init: parallel test runs with full server instances would
            // otherwise panic the second-and-onwards instance with
            // "global default trace dispatcher has already been set".
            let _ = tracing_registry.with(chrome_layer).try_init();
            tracing::info!(
                "Enabling tracing for Chrome. Saving file (after run) to ./trace-timestamp.json",
            );
            return Some(flush_guard);
        }
        crate::config::Tracing::Opentelemetry => {
            #[cfg(feature = "telemetry")]
            {
                use opentelemetry::trace::TracerProvider;
                use opentelemetry::KeyValue;
                use opentelemetry_otlp::WithTonicConfig;
                use opentelemetry_sdk::{
                    logs::SdkLoggerProvider, metrics::SdkMeterProvider, trace::SdkTracerProvider,
                    Resource,
                };

                // The rustls provider tonic's TLS needs is installed at the top of
                // `serve_with_hook`, before this runs. It used to be installed here,
                // which meant a build without OpenTelemetry tracing never installed
                // one at all and panicked as soon as ACME touched rustls.

                let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                    .or_else(|_| std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
                    .unwrap_or_else(|_| "http://localhost:4317".into());
                println!("Enabling OTel gRPC at {}", endpoint);

                let tls = tonic::transport::ClientTlsConfig::new().with_native_roots();

                let resource = Resource::builder()
                    .with_attributes(vec![
                        KeyValue::new("service.name", "atomic-server"),
                        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    ])
                    .build();

                // Traces
                let span_exporter = opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic()
                    .with_tls_config(tls.clone())
                    .build()
                    .expect("build OTLP span exporter");
                let tracer_provider = SdkTracerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(span_exporter)
                    .build();

                // Logs — bridges tracing events to SigNoz logs (linked to traces)
                let log_exporter = opentelemetry_otlp::LogExporter::builder()
                    .with_tonic()
                    .with_tls_config(tls.clone())
                    .build()
                    .expect("build OTLP log exporter");
                let logger_provider = SdkLoggerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(log_exporter)
                    .build();

                // Metrics
                let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
                    .with_tonic()
                    .with_tls_config(tls)
                    .build()
                    .expect("build OTLP metric exporter");
                let meter_provider = SdkMeterProvider::builder()
                    .with_resource(resource)
                    .with_periodic_exporter(metric_exporter)
                    .build();

                let tracer = tracer_provider.tracer("atomic-server");
                let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
                let otel_log_layer =
                    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                        &logger_provider,
                    );
                let terminal_layer = tracing_subscriber::fmt::Layer::default();
                // try_init: see Chrome branch — keeps parallel server tests
                // from panicking after the first one wins the global slot.
                let _ = tracing_registry
                    .with(terminal_layer)
                    .with(otel_trace_layer)
                    .with(otel_log_layer)
                    .try_init();

                opentelemetry::global::set_tracer_provider(tracer_provider);
                opentelemetry::global::set_meter_provider(meter_provider);
            }
            #[cfg(not(feature = "telemetry"))]
            {
                tracing::warn!("OpenTelemetry tracing is not enabled, compile atomic-server with `--features opentelemetry` to enable");
            }
        }
    }

    None
}

/// Starts the Sentry client if `--sentry-dsn` / `SENTRY_DSN` is set. Returns
/// a guard that must be kept alive for the lifetime of the server: dropping it
/// flushes pending events, so hold it in `serve_with_hook` and drop it last.
///
/// Call this *before* `init_tracing`, so the tracing layer has a client to
/// report to, and before the async runtime spawns work, so the panic hook is
/// in place for every task.
///
/// Privacy: this is strictly opt-in. Without a DSN no client is created, no
/// network connection is opened, and nothing about the install ever leaves
/// the machine. A stock self-hosted atomic-server has no DSN.
pub fn init_sentry(config: &crate::config::Config) -> Option<sentry::ClientInitGuard> {
    let dsn = config.opts.sentry_dsn.as_deref()?.trim();
    if dsn.is_empty() {
        return None;
    }
    let options = sentry::ClientOptions::new()
        .dsn(dsn)
        .release(concat!("atomic-server@", env!("CARGO_PKG_VERSION")))
        // Errors only: performance tracing is left at its default (disabled).
        // OpenTelemetry already covers it, and the free Sentry tier has a
        // small event quota.
        .attach_stacktrace(true)
        .before_send(|event| (!is_upstream_unreachable(&event)).then_some(event))
        .send_default_pii(false);
    let guard = sentry::init(options);
    if guard.is_enabled() {
        println!("Sentry error reporting enabled");
    } else {
        eprintln!("SENTRY_DSN is set but invalid; Sentry error reporting is disabled");
    }
    Some(guard)
}

#[cfg(test)]
mod tests {
    use super::{is_upstream_unreachable, reported_by_sentry_actix};

    #[test]
    fn an_unreachable_upstream_is_not_reported() {
        let marker = atomic_lib::errors::UPSTREAM_UNREACHABLE_MARKER;
        let down = sentry::protocol::Event {
            message: Some(format!("{marker}Error when fetching https://x/y")),
            ..Default::default()
        };
        let other = sentry::protocol::Event {
            message: Some("Error handling path Endpoint: boom".into()),
            ..Default::default()
        };
        assert!(is_upstream_unreachable(&down));
        assert!(!is_upstream_unreachable(&other));
    }

    #[test]
    fn request_failures_are_left_to_sentry_actix() {
        // The target `tracing_actix_web`'s own `emit_error_event` logs under.
        assert!(reported_by_sentry_actix("tracing_actix_web::middleware"));
        assert!(reported_by_sentry_actix("tracing_actix_web"));
    }

    #[test]
    fn everything_else_still_reaches_sentry() {
        // Background work has no actix middleware around it, so the tracing
        // layer is the only thing that would ever report these.
        for target in [
            "atomic_server::handlers::commit",
            "atomic_lib::sync::engine",
            "atomic_server",
            "",
        ] {
            assert!(!reported_by_sentry_actix(target), "{target}");
        }
    }
}
