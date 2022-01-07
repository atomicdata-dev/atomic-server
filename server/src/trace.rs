// Start logging / tracing. Creates a subscribers that logs to stdout. Also optionally creates a Chrome trace file.
pub fn init_tracing(config: &crate::config::Config) -> tracing_chrome::FlushGuard {
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

    let (chrome_layer, flush_guard) = tracing_chrome::ChromeLayerBuilder::new()
        .include_args(true)
        .build();
    if config.opts.trace_chrome {
        tracing::info!("Enabling tracing for Chrome");
        tracing_registry.with(chrome_layer).init();
    } else {
        tracing_registry.init();
    }
    flush_guard
}
