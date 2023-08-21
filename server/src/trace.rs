use std::collections::HashMap;

use opentelemetry_otlp::WithExportConfig;

/// Start logging / tracing. Creates a subscribers that logs to stdout.
/// Also optionally creates a Chrome trace file. Starts OpenTelemetry if configured.
/// Returns a [tracing_chrome::FlushGuard] that should be dropped when the server is no longer needed.
pub fn init_tracing(config: &crate::config::Config) -> Option<tracing_chrome::FlushGuard> {
    // Enable logging, but hide most tantivy logs
    let log_level = match config.opts.log_level {
        crate::config::LogLevel::Warn => "warn",
        crate::config::LogLevel::Info => "info",
        crate::config::LogLevel::Debug => "debug",
        crate::config::LogLevel::Trace => "trace",
    };
    std::env::set_var("RUST_LOG", format!("{},tantivy=warn", log_level));
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    // Start tracing
    // STDOUT log
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    let tracing_registry = tracing_subscriber::registry().with(filter);

    match config.opts.trace {
        crate::config::Tracing::Stdout => {
            let terminal_layer = tracing_subscriber::fmt::Layer::default();
            tracing_registry.with(terminal_layer).init();
        }
        crate::config::Tracing::Chrome => {
            let (chrome_layer, flush_guard) = tracing_chrome::ChromeLayerBuilder::new()
                .include_args(true)
                .build();
            tracing_registry.with(chrome_layer).init();
            tracing::info!(
                "Enabling tracing for Chrome. Saving file (after run) to ./trace-timestamp.json",
            );
            return Some(flush_guard);
        }
        crate::config::Tracing::OpenTelemetry => {
            #[cfg(feature = "telemetry")]
            {
                let endpoint =
                    "https://api.openobserve.ai/api/joep_organization_2642_75oYwOBs0D0s8am/traces";
                let token = "am9lcEBvbnRvbGEuaW86Mjg3SjBZV2JlNHhPRTlTMTU2eTM=";
                let mut headers = HashMap::new();
                headers.insert("Authorization".to_string(), format!("Basic {}", token));

                let otlp_exporter = opentelemetry_otlp::new_exporter()
                    .http()
                    .with_headers(headers)
                    .with_endpoint(endpoint)
                    .with_http_client(opentelemetry_http::hyper::HyperClient::new_with_timeout_and_authorization_header(
                        ,
                    ));
                let tracer = opentelemetry_otlp::new_pipeline()
                    .tracing()
                    .with_exporter(otlp_exporter)
                    .install_simple()
                    .expect("Opentelementy");

                let layer = tracing_opentelemetry::layer().with_tracer(tracer);
                tracing_registry.with(layer).init();
            }
            #[cfg(not(feature = "telemetry"))]
            {
                tracing::warn!("OpenTelemetry tracing is not enabled, compile atomic-server with `--features opentelemetry` to enable");
            }
        }

        crate::config::Tracing::Jaeger => {
            #[cfg(feature = "telemetry")]
            {
                println!("Enabling tracing for OpenTelemetry and Jaeger");
                let tracer = opentelemetry_jaeger::new_agent_pipeline()
                    .with_service_name("atomic-server")
                    .install_simple()
                    .expect("Error initializing Jaeger exporter");

                let layer = tracing_opentelemetry::layer().with_tracer(tracer);
                tracing_registry.with(layer).init();
            }
            #[cfg(not(feature = "telemetry"))]
            {
                tracing::warn!("OpenTelemetry tracing is not enabled, compile atomic-server with `--features opentelemetry` to enable");
            }
        }
    }

    None
}
