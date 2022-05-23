// Start logging / tracing. Creates a subscribers that logs to stdout. Also optionally creates a Chrome trace file.
pub fn init_tracing(config: &crate::config::Config) -> Option<tracing_chrome::FlushGuard> {
    // Enable logging, but hide most tantivy logs
    std::env::set_var(
        "RUST_LOG",
        format!("{},tantivy=warn", config.opts.log_level),
    );
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    // Start tracing
    // STDOUT log
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    let terminal_layer = tracing_subscriber::fmt::Layer::default();
    let tracing_registry = tracing_subscriber::registry()
        .with(terminal_layer)
        .with(filter);

    if config.opts.trace_chrome {
        let (chrome_layer, flush_guard) = tracing_chrome::ChromeLayerBuilder::new()
            .include_args(true)
            .build();
        tracing_registry.with(chrome_layer).init();
        tracing::info!(
            "Enabling tracing for Chrome. Saving file (after run) to ./trace-timestamp.json",
        );
        return Some(flush_guard);
    } else {
        tracing_registry.init();
    }
    None
}
