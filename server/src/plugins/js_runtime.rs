//! Runs a plugin's JavaScript server-side.
//!
//! The counterpart to the browser's Worker: same contract, same determinism,
//! different placement. A run lands here when it needs the network, a secret,
//! or when nobody is watching — everything a browser placement cannot give it.
//!
//! One component runs every plugin. The script is an argument, not an artifact,
//! so promoting a plugin from the browser to the server is a decision rather
//! than a build.

use std::sync::Arc;

use atomic_lib::Db;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::errors::AtomicServerResult;

mod bindings {
    wasmtime::component::bindgen!({
        path: "wit/plugin-runtime.wit",
        world: "plugin-runtime",
        imports: { default: async },
        exports: { default: async },
    });
}

/// A plugin gets one run's worth of resources, then the instance is dropped.
/// Nothing survives to the next run — not a timer, not a global, not a leak.
const FUEL: u64 = 20_000_000_000;
const MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// What the host will do on a plugin's behalf.
///
/// A trait rather than a concrete type so the guards can be tested without a
/// store, and so a future placement (a CLI, a test harness) can supply its own.
#[async_trait::async_trait]
pub trait PluginHost: Send + 'static {
    async fn fetch(&mut self, request: String) -> Result<String, String>;
    async fn get_resource(&mut self, subject: String) -> Result<String, String>;
    async fn query(&mut self, property: String, value: String) -> Result<String, String>;
}

struct RuntimeState<H: PluginHost> {
    table: ResourceTable,
    ctx: WasiCtx,
    limits: StoreLimits,
    host: H,
}

impl<H: PluginHost> WasiView for RuntimeState<H> {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl<H: PluginHost> bindings::atomic::plugin_runtime::host::Host for RuntimeState<H> {
    async fn fetch(&mut self, request: String) -> Result<String, String> {
        self.host.fetch(request).await
    }

    async fn get_resource(&mut self, subject: String) -> Result<String, String> {
        self.host.get_resource(subject).await
    }

    async fn query(&mut self, property: String, value: String) -> Result<String, String> {
        self.host.query(property, value).await
    }
}

/// The compiled runtime, kept for the process' lifetime.
///
/// Compiling the component is the expensive part; instantiating it is not, so
/// this is built once and every run gets a fresh instance from it.
pub struct JsRuntime {
    engine: Engine,
    component: Component,
}

impl JsRuntime {
    pub fn from_bytes(bytes: &[u8]) -> AtomicServerResult<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);

        let engine =
            Engine::new(&config).map_err(|e| format!("could not create a wasm engine: {e}"))?;
        let component = Component::from_binary(&engine, bytes)
            .map_err(|e| format!("plugin runtime is not a valid component: {e}"))?;

        Ok(Self { engine, component })
    }

    /// Runs `source` and returns the verdict as JSON.
    ///
    /// The verdict is not parsed here: the host's `parseVerdict` already knows
    /// how to distrust it, and doing that twice in two languages is how the two
    /// come to disagree.
    pub async fn run<H: PluginHost>(
        &self,
        source: &str,
        input: &str,
        host: H,
    ) -> AtomicServerResult<Result<String, String>> {
        let mut linker: Linker<RuntimeState<H>> = Linker::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| format!("could not link WASI: {e}"))?;
        bindings::PluginRuntime::add_to_linker::<_, wasmtime::component::HasSelf<_>>(
            &mut linker,
            |s| s,
        )
        .map_err(|e| format!("could not link the plugin host: {e}"))?;

        let mut store = Store::new(
            &self.engine,
            RuntimeState {
                table: ResourceTable::new(),
                // No stdio, no filesystem, no sockets. Everything a plugin can
                // reach is an import the host wrote.
                ctx: WasiCtxBuilder::new().build(),
                limits: StoreLimitsBuilder::new().memory_size(MEMORY_BYTES).build(),
                host,
            },
        );

        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(FUEL)
            .map_err(|e| format!("could not meter the plugin: {e}"))?;

        let instance =
            bindings::PluginRuntime::instantiate_async(&mut store, &self.component, &linker)
                .await
                .map_err(|e| format!("could not start the plugin runtime: {e}"))?;

        match instance.call_run(&mut store, source, input).await {
            Ok(result) => Ok(result),
            // A trap is a plugin that ran out of fuel or memory, which is a
            // problem to report rather than an error to propagate: the run
            // failed, the server did not.
            Err(e) => Ok(Err(format!("the plugin was stopped: {e}"))),
        }
    }
}

/// The runtime component, built and embedded by `build.rs`.
///
/// Empty when the build could not produce it — a toolchain without
/// `wasm32-wasip2`. That is a degraded server rather than a broken one, so the
/// absence is reported where someone tries to use it.
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/plugin_runtime.wasm"));

/// The embedded runtime, compiled once for the process.
pub fn embedded_runtime() -> AtomicServerResult<Arc<JsRuntime>> {
    if EMBEDDED.is_empty() {
        return Err(
            "this server was built without the plugin runtime, so plugins cannot run server-side. Rebuild with the wasm32-wasip2 target installed."
                .into(),
        );
    }

    Ok(Arc::new(JsRuntime::from_bytes(EMBEDDED)?))
}

/// Adapts a store to what a plugin may do. Not yet wired to secrets or the
/// egress guard; those arrive with the endpoint that uses this.
pub struct StoreHost {
    pub db: Arc<Db>,
}

#[async_trait::async_trait]
impl PluginHost for StoreHost {
    async fn fetch(&mut self, _request: String) -> Result<String, String> {
        Err("fetch is not wired up for this placement yet".to_string())
    }

    async fn get_resource(&mut self, subject: String) -> Result<String, String> {
        use atomic_lib::Storelike;

        let resource = self
            .db
            .get_resource(&subject.into())
            .await
            .map_err(|e| e.to_string())?;

        resource.to_json_ad(None).map_err(|e| e.to_string())
    }

    async fn query(&mut self, _property: String, _value: String) -> Result<String, String> {
        Err("query is not wired up for this placement yet".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what the plugin asked for and answers with canned data.
    struct FakeHost {
        fetched: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl PluginHost for FakeHost {
        async fn fetch(&mut self, request: String) -> Result<String, String> {
            self.fetched.lock().unwrap().push(request);

            Ok(r#"{"status":200,"body":"{\"name\":\"Ada\"}"}"#.to_string())
        }

        async fn get_resource(&mut self, subject: String) -> Result<String, String> {
            Ok(format!("{{\"@id\":\"{subject}\"}}"))
        }

        async fn query(&mut self, _p: String, _v: String) -> Result<String, String> {
            Ok("[\"https://x/a\"]".to_string())
        }
    }

    /// The runtime as the server actually ships it.
    ///
    /// Not read from `target/`: a test that quietly skips when an artifact is
    /// missing is a test that reports success for having run nothing. If the
    /// build could not embed the runtime, these fail and say why.
    fn runtime() -> JsRuntime {
        assert!(
            !EMBEDDED.is_empty(),
            "no plugin runtime was embedded; install the wasm32-wasip2 target and rebuild",
        );

        JsRuntime::from_bytes(EMBEDDED).expect("the embedded runtime is a valid component")
    }

    const INPUT: &str = r#"{"trigger":{"kind":"manual","at":1700000000000}}"#;

    fn host() -> (FakeHost, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let fetched = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        (
            FakeHost {
                fetched: fetched.clone(),
            },
            fetched,
        )
    }

    #[tokio::test]
    async fn runs_a_plugin_and_returns_its_verdict() {
        let runtime = runtime();
        let (h, _) = host();

        let verdict = runtime
            .run(
                "function run() { return { intents: [], problems: [], sum: [1,2,3].reduce((a,b)=>a+b,0) }; }",
                INPUT,
                h,
            )
            .await
            .unwrap()
            .expect("ran");

        assert!(verdict.contains("\"sum\":6"));
    }

    #[tokio::test]
    async fn a_plugin_reaches_the_host() {
        let runtime = runtime();
        let (h, fetched) = host();

        let verdict = runtime
            .run(
                r#"function run(ctx) {
                     const res = ctx.http({ method: "GET", url: "https://api.test/me" });
                     const body = JSON.parse(res.body);
                     return { intents: [], problems: [], name: body.name };
                   }"#,
                INPUT,
                h,
            )
            .await
            .unwrap()
            .expect("ran");

        assert!(verdict.contains("Ada"));
        assert!(fetched.lock().unwrap()[0].contains("https://api.test/me"));
    }

    #[tokio::test]
    async fn the_clock_and_the_prng_match_the_browser_placement() {
        let runtime = runtime();

        let once = || async {
            let (h, _) = host();
            runtime
                .run(
                    "function run() { return { at: Date.now(), iso: new Date().toISOString(), r: Math.random() }; }",
                    INPUT,
                    h,
                )
                .await
                .unwrap()
                .expect("ran")
        };

        let first = once().await;

        // Frozen to the trigger, exactly as `plugin-sandbox.ts` does it.
        assert!(first.contains("\"at\":1700000000000"));
        assert!(first.contains("2023-11-14T22:13:20.000Z"));

        // And seeded from the input, so two runs over one input agree. Without
        // this a fixture proves nothing.
        assert_eq!(first, once().await);
    }

    #[tokio::test]
    async fn a_plugin_that_throws_reports_where() {
        let runtime = runtime();
        let (h, _) = host();

        let error = runtime
            .run(
                "function run() { throw new TypeError('no column called email'); }",
                INPUT,
                h,
            )
            .await
            .unwrap()
            .expect_err("threw");

        // An LLM reads this back to fix its own code, so the message has to
        // survive the boundary.
        assert!(error.contains("no column called email"), "{error}");
    }

    #[tokio::test]
    async fn a_plugin_with_a_syntax_error_says_so() {
        let runtime = runtime();
        let (h, _) = host();

        let error = runtime
            .run("function run() { this is not javascript }", INPUT, h)
            .await
            .unwrap()
            .expect_err("refused");

        assert!(error.contains("plugin source"), "{error}");
    }

    #[tokio::test]
    async fn a_runaway_plugin_is_stopped_rather_than_the_server() {
        let runtime = runtime();
        let (h, _) = host();

        let error = runtime
            .run("function run() { while (true) {} }", INPUT, h)
            .await
            .unwrap()
            .expect_err("stopped");

        assert!(error.contains("stopped"), "{error}");
    }

    #[tokio::test]
    async fn a_plugin_has_no_ambient_io() {
        let runtime = runtime();
        let (h, _) = host();

        let verdict = runtime
            .run(
                "function run() { return { hasFetch: typeof fetch, hasProcess: typeof process }; }",
                INPUT,
                h,
            )
            .await
            .unwrap()
            .expect("ran");

        assert!(verdict.contains("\"hasFetch\":\"undefined\""), "{verdict}");
        assert!(
            verdict.contains("\"hasProcess\":\"undefined\""),
            "{verdict}"
        );
    }
}
