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

use atomic_lib::{agents::ForAgent, Db};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store, StoreLimits};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::errors::AtomicServerResult;

pub use super::host_core::PluginHost;
use super::host_core::{self, FetchRequest, HostCore, ResourceGrants, Runtime};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../plugin-runtime/wit/plugin-runtime.wit",
        world: "plugin-runtime",
        imports: { default: async },
        exports: { default: async },
    });
}

// Captured from the host input before JS starts. Mutating ctx.trigger cannot
// change the ownership identity used by a capability call.
fn consumer_run(input: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(input).ok()?;
    let id = value["trigger"]["id"].as_str()?;
    match value["trigger"]["kind"].as_str()? {
        "query" => Some(format!("query:{id}")),
        "cron" if id.starts_with("cron:") => Some(id.into()),
        _ => None,
    }
}

struct RuntimeState<H: PluginHost> {
    table: ResourceTable,
    ctx: WasiCtx,
    limits: StoreLimits,
    host: H,
    source_hash: String,
    allow_automatic: bool,
    consumer_run: Option<String>,
    waits: Vec<serde_json::Value>,
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
    async fn invoke_action(&mut self, request: String) -> Result<String, String> {
        let output = self
            .host
            .invoke_action(
                request,
                &self.source_hash,
                self.allow_automatic,
                self.consumer_run.as_deref(),
            )
            .await?;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&output) {
            if value["status"] == "needs_review" {
                self.waits.push(serde_json::json!({"connection":value["connection"],"id":value["proposal"]["id"],"release":value["proposal"]["release"]}));
            }
        }
        Ok(output)
    }
    async fn abi(
        &mut self,
        function: String,
        args: String,
    ) -> Result<String, bindings::atomic::plugin_runtime::host::Error> {
        self.host.abi(&function, &args).await.map_err(|e| {
            bindings::atomic::plugin_runtime::host::Error {
                code: e.code,
                message: e.message,
            }
        })
    }
}

/// The compiled runtime, kept for the process' lifetime.
///
/// Compiling the component is the expensive part; instantiating it is not, so
/// this is built once and every run gets a fresh instance from it.
pub struct JsRuntime {
    engine: Arc<Engine>,
    component: Component,
}

impl JsRuntime {
    pub fn from_bytes(bytes: &[u8]) -> AtomicServerResult<Self> {
        let engine = host_core::engine()?;
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
        self.run_inner(source, input, host, false).await
    }
    pub(crate) async fn run_triggered<H: PluginHost>(
        &self,
        source: &str,
        input: &str,
        host: H,
    ) -> AtomicServerResult<Result<String, String>> {
        self.run_inner(source, input, host, true).await
    }
    async fn run_inner<H: PluginHost>(
        &self,
        source: &str,
        input: &str,
        host: H,
        trusted_trigger: bool,
    ) -> AtomicServerResult<Result<String, String>> {
        let mut linker: Linker<RuntimeState<H>> = Linker::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| format!("could not link WASI: {e}"))?;
        bindings::PluginRuntime::add_to_linker::<_, wasmtime::component::HasSelf<_>>(
            &mut linker,
            |s| s,
        )
        .map_err(|e| format!("could not link the plugin host: {e}"))?;

        // A plugin gets one run's worth of resources, then the instance is
        // dropped. Nothing survives to the next run — not a timer, not a
        // global, not a leak. How much it gets is decided by the capabilities
        // its installation was granted.
        let mut host = host;
        let limits = host_core::limits(Runtime::Js, host.resource_grants().await);

        let mut store = Store::new(
            &self.engine,
            RuntimeState {
                table: ResourceTable::new(),
                // No stdio, no filesystem, no sockets. Everything a plugin can
                // reach is an import the host wrote.
                ctx: WasiCtxBuilder::new().build(),
                limits: limits.store_limits(),
                host,
                source_hash: blake3::hash(source.as_bytes()).to_hex().to_string(),
                allow_automatic: trusted_trigger
                    && serde_json::from_str::<serde_json::Value>(input)
                        .ok()
                        .is_some_and(|v| {
                            matches!(v["trigger"]["kind"].as_str(), Some("query" | "cron"))
                        }),
                consumer_run: trusted_trigger.then(|| consumer_run(input)).flatten(),
                waits: Vec::new(),
            },
        );

        store.limiter(|state| &mut state.limits);
        limits.meter(&mut store)?;

        let instance =
            bindings::PluginRuntime::instantiate_async(&mut store, &self.component, &linker)
                .await
                .map_err(|e| format!("could not start the plugin runtime: {e}"))?;

        match instance.call_run(&mut store, source, input).await {
            Ok(result) => {
                if !store.data().waits.is_empty() {
                    return Ok(Ok(serde_json::json!({"integrationWaits":store.data().waits,"intents":[],"problems":[{"severity":"error","message":"Waiting for integration approval. Review the action on its connection."}]}).to_string()));
                }
                Ok(result)
            }
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

    static RUNTIME: std::sync::OnceLock<Result<Arc<JsRuntime>, String>> =
        std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            JsRuntime::from_bytes(EMBEDDED)
                .map(Arc::new)
                .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(Into::into)
}

/// What a server-placed plugin may do.
///
/// Every capability here already exists as guarded host code; this only decides
/// which of them a plugin gets and under whose name.
#[derive(Clone)]
pub struct StoreHost {
    pub db: Arc<Db>,
    /// Whose secrets may be spent, and whose origins bound the fetch.
    pub plugin: String,
    pub drive: String,
    pub for_agent: ForAgent,
    pub manifest: Option<super::manifest::Manifest>,
}

pub(super) struct NoCapabilities;
#[async_trait::async_trait]
impl PluginHost for NoCapabilities {}

pub async fn describe_manifest(source: &str) -> Result<Option<super::manifest::Manifest>, String> {
    let raw = embedded_runtime()
        .map_err(|e| e.to_string())?
        .run(
            source,
            r#"{"trigger":{"kind":"manual","at":0},"describe":true}"#,
            NoCapabilities,
        )
        .await
        .map_err(|e| e.to_string())??;
    super::manifest::Manifest::parse(serde_json::from_str(&raw).map_err(|e| e.to_string())?)
}

impl StoreHost {
    /// A host for `plugin` installed in `drive`, running as `for_agent`, with
    /// the binding already validated (plugin exists, installed in the drive,
    /// agent may write the plugin).
    pub async fn bound(
        db: &Db,
        drive: &str,
        plugin: &str,
        for_agent: ForAgent,
        manifest: Option<super::manifest::Manifest>,
    ) -> Result<Self, String> {
        let host = StoreHost {
            db: Arc::new(db.clone()),
            plugin: plugin.into(),
            drive: drive.into(),
            for_agent,
            manifest,
        };
        host.validate_binding().await?;
        Ok(host)
    }

    pub async fn validate_binding(&self) -> Result<(), String> {
        use atomic_lib::{hierarchy::check_write, Storelike};
        let resource = self
            .db
            .get_resource(&self.plugin.as_str().into())
            .await
            .map_err(|e| e.to_string())?;
        super::installation::resolve(self.db.as_ref(), &self.drive, &self.plugin).await?;
        check_write(self.db.as_ref(), &resource, &self.for_agent)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The shared host under this run's grant.
    ///
    /// Built per call rather than once: the installation is resolved each
    /// time, so a revocation between two calls of one run takes effect on the
    /// second.
    pub(crate) async fn core(&self) -> Result<HostCore, String> {
        HostCore::for_run(
            self.db.clone(),
            &self.drive,
            &self.plugin,
            self.for_agent.clone(),
            self.manifest.clone(),
        )
        .await
    }
}

#[derive(serde::Deserialize)]
struct JsRequest {
    #[serde(default)]
    operation: Option<String>,
    #[serde(default = "default_method")]
    method: String,
    url: String,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

impl From<JsRequest> for FetchRequest {
    fn from(request: JsRequest) -> Self {
        FetchRequest {
            operation: request.operation,
            method: request.method,
            url: request.url,
            headers: request.headers.into_iter().collect(),
            body: request.body,
        }
    }
}

#[async_trait::async_trait]
impl PluginHost for StoreHost {
    async fn invoke_action(
        &mut self,
        request: String,
        source_hash: &str,
        allow_automatic: bool,
        consumer: Option<&str>,
    ) -> Result<String, String> {
        super::actions::invoke_from_plugin_run(
            self,
            &request,
            source_hash,
            allow_automatic,
            consumer,
        )
        .await
    }
    async fn abi(
        &mut self,
        function: &str,
        args: &str,
    ) -> Result<String, super::host_abi::HostError> {
        // No shared registry here: `calls.*` loads the drive's apps afresh.
        // Runs that should share one are wrapped in `host_abi::JsAbi`.
        super::host_abi::JsAbi::new(self.clone(), Default::default())
            .abi(function, args)
            .await
    }

    async fn resource_grants(&mut self) -> ResourceGrants {
        host_core::installation_grants(&self.db, &self.drive, &self.plugin, self.manifest.as_ref())
            .await
    }
}

impl StoreHost {
    /// A fetch as the JS guest describes it: a JSON request in, a JSON
    /// `{ status, body }` out. Every check in between is the shared host's.
    pub(crate) async fn request(
        &mut self,
        request: String,
        effect: &str,
    ) -> Result<String, String> {
        let request: JsRequest =
            serde_json::from_str(&request).map_err(|e| format!("not a request: {e}"))?;

        let response = self.core().await?.fetch(request.into(), effect).await?;

        serde_json::to_string(&serde_json::json!({
            "status": response.status,
            "body": response.body,
        }))
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    struct ConsumerProbe;
    #[async_trait::async_trait]
    impl PluginHost for ConsumerProbe {
        async fn invoke_action(
            &mut self,
            _: String,
            _: &str,
            automatic: bool,
            run: Option<&str>,
        ) -> Result<String, String> {
            Ok(serde_json::json!({"status":"read","automatic":automatic,"run":run}).to_string())
        }
    }
    #[actix_rt::test]
    async fn only_host_triggered_runs_own_receipts_and_js_cannot_change_the_identity() {
        let runtime = embedded_runtime().unwrap();
        let source = "export function run(ctx) { ctx.trigger.id = 'forged'; return {intents:[],probe:ctx.integration({})}; }";
        let input = r#"{"trigger":{"kind":"query","id":"original"}}"#;
        let manual: serde_json::Value = serde_json::from_str(
            &runtime
                .run(source, input, ConsumerProbe)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manual["probe"]["automatic"], false);
        assert!(manual["probe"]["run"].is_null());
        let triggered: serde_json::Value = serde_json::from_str(
            &runtime
                .run_triggered(source, input, ConsumerProbe)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(triggered["probe"]["automatic"], true);
        assert_eq!(triggered["probe"]["run"], "query:original");
    }

    use super::*;
    use serde_json::json;

    #[actix_rt::test]
    async fn manifests_are_evaluated_without_host_access() {
        assert!(describe_manifest(
            "__atomic.read('private'); export const manifest = {schemaVersion:1};"
        )
        .await
        .is_err());
        let manifest = describe_manifest("export const manifest = {schemaVersion:1, operations:[{id:'list',method:'GET',url:'https://api.test/items',effect:'read'}]};").await.unwrap().unwrap();
        assert_eq!(manifest.operations.len(), 1);
    }

    #[actix_rt::test]
    async fn plugin_host_cannot_read_unrelated_private_resources() {
        use atomic_lib::{urls, Storelike, Value};
        let mut fixture = crate::plugins::test_fixture::fixture("host_private_read").await;
        crate::plugins::test_fixture::write_plugin(&mut fixture, "Owned plugin").await;
        let author = "did:ad:agent:plugin-author";
        let mut plugin = fixture
            .appstate
            .store
            .get_resource(&fixture.plugin.as_str().into())
            .await
            .unwrap();
        plugin
            .set_unsafe(
                urls::WRITE.into(),
                Value::ResourceArray(vec![author.into()]),
            )
            .unwrap();
        plugin
            .set_unsafe(urls::READ.into(), Value::ResourceArray(vec![author.into()]))
            .unwrap();
        plugin.save(&fixture.appstate.store).await.unwrap();
        let store = &fixture.appstate.store;
        let hidden = crate::plugins::test_fixture::genesis(
            store,
            vec![
                (urls::NAME, Value::String("private-host-record".into())),
                (
                    urls::READ,
                    Value::ResourceArray(vec!["did:ad:agent:unrelated".into()]),
                ),
            ],
        )
        .await;
        let mut host = StoreHost {
            db: Arc::new(store.clone()),
            drive: fixture.drive,
            plugin: fixture.plugin,
            for_agent: ForAgent::AgentSubject(author.into()),
            manifest: None,
        };
        assert!(host
            .abi(
                "net.fetch",
                r#"[{"method":"DELETE","url":"https://api.test/items"}]"#
            )
            .await
            .unwrap_err()
            .message
            .contains("legacy preview"));
        host.validate_binding().await.unwrap();
        let drive = host.drive.clone();
        host.drive = "did:ad:another-drive".into();
        assert!(host
            .validate_binding()
            .await
            .unwrap_err()
            .contains("does not belong"));
        host.drive = drive;
        assert!(host
            .abi("store.get", &json!([hidden]).to_string())
            .await
            .is_err());
        let matches = host
            .abi(
                "store.query",
                &json!([{"filters": [{"property": urls::NAME, "op": "eq", "value": {"tag": "string", "val": "private-host-record"}}]}]).to_string(),
            )
            .await
            .unwrap();
        assert!(!matches.contains(&hidden));
        use crate::plugins::plan::PlanHost;
        let mut planner = crate::plugins::store_host::StoreApplyHost {
            store: store.clone(),
            for_agent: ForAgent::AgentSubject(author.into()),
            signing_as: None,
        };
        assert!(planner.read_resource(&hidden).await.is_none());
        // The account may read its plugin, but attaching an app identity must
        // restrict access to the intersection, not inherit the account's ACL.
        assert!(host
            .abi("store.get", &json!([host.plugin]).to_string())
            .await
            .is_ok());
        let app = atomic_lib::agents::Agent::new(None).unwrap();
        store
            .set_app_agent(
                &atomic_lib::db::app_agent::AppAgentKey::new(&host.drive, &host.plugin),
                &atomic_lib::db::app_agent::AppAgent::new(
                    app.subject.to_string(),
                    app.build_secret().unwrap(),
                    0,
                ),
            )
            .unwrap();
        assert!(host
            .abi("store.get", &json!([host.plugin]).to_string())
            .await
            .is_err());
    }

    /// Records what the plugin asked for and answers with canned data.
    struct FakeHost {
        fetched: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl PluginHost for FakeHost {
        async fn abi(
            &mut self,
            _: &str,
            args: &str,
        ) -> Result<String, crate::plugins::host_abi::HostError> {
            self.fetched.lock().unwrap().push(args.to_string());

            Ok(r#"{"status":200,"body":"{\"name\":\"Ada\"}"}"#.to_string())
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
                "export function run() { return { intents: [], problems: [], sum: [1,2,3].reduce((a,b)=>a+b,0) }; }",
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
                r#"export function run(ctx) {
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
                    "export function run() { return { at: Date.now(), iso: new Date().toISOString(), r: Math.random() }; }",
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
                "export function run() { throw new TypeError('no column called email'); }",
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
            .run("export function run() { this is not javascript }", INPUT, h)
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
            .run("export function run() { while (true) {} }", INPUT, h)
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
                "export function run() { return { hasFetch: typeof fetch, hasProcess: typeof process }; }",
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
