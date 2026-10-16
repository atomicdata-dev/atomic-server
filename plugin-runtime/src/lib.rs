//! The component that runs Atomic plugins.
//!
//! One instance per run, one binary for every plugin: the script arrives as a
//! string rather than as its own compiled artifact, so a plugin can move from
//! the browser to the server without being rebuilt.
//!
//! The determinism rules here mirror `plugin-sandbox.ts` in the browser
//! exactly. A plugin is run on a fixture, on a sample, and then unattended on
//! the server; if `Date.now()` or `Math.random()` answered differently in the
//! two placements, none of those checks would mean anything.

wit_bindgen::generate!({
    path: "wit",
    world: "plugin-runtime",
});

use crate::atomic::plugin_runtime::host;
use rquickjs::{Context, Function, Module, Runtime};

struct Component;

/// Installed before the plugin's own source.
///
/// Everything a plugin can reach that is not plain JavaScript is defined here,
/// so the surface is one readable file rather than a set of host functions
/// discovered by trial.
const PRELUDE: &str = r#"
globalThis.__atomic = (function () {
  const input = JSON.parse(__inputJson);

  // The only clock. Frozen to the trigger so two runs over one input agree —
  // the browser sandbox does the same, and fixtures depend on it.
  const frozen = input.trigger.at;
  const NativeDate = Date;

  class FrozenDate extends NativeDate {
    constructor(...args) {
      if (args.length === 0) super(frozen);
      else super(...args);
    }
    static now() { return frozen; }
  }

  globalThis.Date = FrozenDate;

  // mulberry32, seeded from the input, matching the browser.
  let seed = input.seed !== undefined ? input.seed : hashInput(input);
  globalThis.Math.random = function () {
    seed = (seed + 0x6d2b79f5) >>> 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  function hashInput(i) {
    const text = `${i.trigger.kind}:${i.trigger.at}:${i.cursor ?? ''}`;
    let hash = 2166136261;
    for (let n = 0; n < text.length; n++) {
      hash ^= text.charCodeAt(n);
      hash = Math.imul(hash, 16777619);
    }
    return hash >>> 0;
  }

  function unwrap(result) {
    const parsed = JSON.parse(result);
    if (parsed.error !== undefined) throw new Error(parsed.error);
    return parsed.ok;
  }

  input.integration = function (request) {
    return JSON.parse(unwrap(__hostAction(JSON.stringify(request))));
  };
  // The host ABI (`atomic:host`): the same functions, names and error codes as
  // every other kind of app. A failure throws an Error with `.code`.
  function abi(name, ...args) {
    const r = JSON.parse(__hostAbi(name, JSON.stringify(args)));
    if (r.error !== undefined) throw Object.assign(new Error(r.error.message), { code: r.error.code });
    return JSON.parse(r.ok);
  }
  globalThis.store = {
    get: (subject) => abi('store.get', subject),
    getMany: (subjects) => abi('store.get-many', subjects),
    query: (spec) => abi('store.query', spec),
    apply: (intents) => abi('store.apply', intents),
  };
  globalThis.net = { fetch: (request) => abi('net.fetch', request) };
  globalThis.calls = {
    providers: (name) => abi('calls.providers', name),
    describe: (name) => abi('calls.describe', name),
    call: (name, fn, args, handles = []) => abi('calls.call', name, fn, args, handles),
  };

  // The older `ctx.*` names, as thin shims over the ABI with their old shapes:
  // `http` takes a URL request, `read` returns JSON-AD, `query` returns
  // subjects matching an exact string value.
  input.http = (request) => abi('net.fetch', request);
  input.read = (subject) => {
    const { subject: id, propvals } = abi('store.get', subject);
    return Object.fromEntries([['@id', id], ...propvals.map((pv) => [pv.property, pv.value.val])]);
  };
  input.query = (property, value) => {
    const subjects = [];
    let cursor = null;
    do {
      const page = abi('store.query', {
        filters: [{ property, op: 'eq', value: { tag: 'string', val: value } }],
        limit: 500,
        cursor,
      });
      subjects.push(...page.subjects);
      if (!page.complete && !page.cursor) throw new Error('sandbox query is incomplete');
      cursor = page.cursor;
    } while (cursor);
    return subjects;
  };

  return input;
})();
"#;

impl Guest for Component {
    fn run(source: String, input: String) -> Result<String, String> {
        let runtime = Runtime::new().map_err(|e| e.to_string())?;
        let context = Context::full(&runtime).map_err(|e| e.to_string())?;

        context.with(|ctx| {
            let globals = ctx.globals();

            globals
                .set("__inputJson", input)
                .map_err(|e| e.to_string())?;

            // Host imports are handed to JS as ordinary functions. Each returns
            // `{ok}` or `{error}` as JSON: a WIT `result` has no JS equivalent,
            // and a thrown string loses which call failed.
            globals
                .set(
                    "__hostAction",
                    Function::new(ctx.clone(), |request: String| {
                        encode(host::invoke_action(&request))
                    })
                    .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;

            globals
                .set(
                    "__hostAbi",
                    Function::new(
                        ctx.clone(),
                        |function: String, args: String| match host::abi(&function, &args) {
                            Ok(value) => encode(Ok(value)),
                            Err(e) => format!(
                                "{{\"error\":{{\"code\":{},\"message\":{}}}}}",
                                serde_json_string(&e.code),
                                serde_json_string(&e.message)
                            ),
                        },
                    )
                    .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;

            ctx.eval::<(), _>(PRELUDE)
                .map_err(|e| describe(&ctx, e, "runtime prelude"))?;

            // Evaluated as a module, not a script. The browser placement
            // imports the source as an ES module, so `export function run`
            // is the shape every plugin is written in — including the starter.
            // Evaluating it as a script made that a syntax error, which meant
            // no plugin at all could run server-side.
            let (module, promise) = Module::declare(ctx.clone(), "plugin", source)
                .map_err(|e| describe(&ctx, e, "plugin source"))?
                .eval()
                .map_err(|e| describe(&ctx, e, "plugin source"))?;

            // A module body may await; finish it before reaching for `run`.
            promise
                .finish::<()>()
                .map_err(|e| describe(&ctx, e, "plugin source"))?;

            if ctx
                .eval::<bool, _>("__atomic.describe === true")
                .unwrap_or(false)
            {
                let manifest: rquickjs::Value = module
                    .get("manifest")
                    .unwrap_or_else(|_| rquickjs::Value::new_null(ctx.clone()));
                globals
                    .set("__manifest", manifest)
                    .map_err(|e| e.to_string())?;
                return ctx
                    .eval::<String, _>("JSON.stringify(__manifest ?? null)")
                    .map_err(|e| describe(&ctx, e, "manifest"));
            }

            let run: Function = module
                .get("run")
                .map_err(|_| "the plugin does not export a run() function".to_string())?;

            globals.set("__run", run).map_err(|e| e.to_string())?;

            // `run` returns the verdict; the host parses and validates it, so
            // anything shaped wrong is reported in the preview rather than here.
            ctx.eval::<rquickjs::Promise, _>(
                "(async () => JSON.stringify((await __run(__atomic)) ?? null))()",
            )
            .and_then(|promise| promise.finish::<String>())
            .map_err(|e| describe(&ctx, e, "run()"))
        })
    }
}

fn encode(result: Result<String, String>) -> String {
    match result {
        Ok(value) => format!("{{\"ok\":{}}}", serde_json_string(&value)),
        Err(error) => format!("{{\"error\":{}}}", serde_json_string(&error)),
    }
}

/// Minimal JSON string escaping. Pulling in serde here would add weight to a
/// component whose whole appeal is being small.
fn serde_json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');

    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }

    out.push('"');
    out
}

/// A JS error with its message and stack.
///
/// The plugin author is usually an LLM reading this back to fix its own code,
/// so "Error" alone is worthless — the line and the stack are the whole point.
fn describe(ctx: &rquickjs::Ctx<'_>, error: rquickjs::Error, during: &str) -> String {
    if let rquickjs::Error::Exception = error {
        let exception = ctx.catch();

        if let Some(exception) = exception.as_exception() {
            let message = exception.message().unwrap_or_default();
            let stack = exception.stack().unwrap_or_default();

            return if stack.is_empty() {
                format!("{during}: {message}")
            } else {
                format!("{during}: {message}\n{stack}")
            };
        }
    }

    format!("{during}: {error}")
}

export!(Component);
