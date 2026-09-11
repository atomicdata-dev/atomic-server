# Sentry → Codex → draft PR

One central runner covers the Atomic suite; no changes to SaaS application code
are needed. Sentry MCP was used to verify the three project slugs in the example
configuration. Each Codex investigation uses that same configured Sentry MCP for
details. No Sentry API token is copied into this project.

**Not activated.** Local tests validate plumbing with synthetic events and mocked
Codex/GitHub calls. They do not establish live Sentry delivery, Codex authentication,
successful bug fixes, or GitHub publication.

## Configure and run

Requires Python 3.11+, Git, authenticated `gh`, and an authenticated `codex` CLI
with working Sentry MCP access. Use a dedicated automation account/host with only
the intended integrations. The runner keeps Codex's workspace sandbox and approval
policy. An unattended command that needs approval may block; inspect its report.
`codex_command` selects the executable. The macOS example uses the installed app's
bundled CLI. Both Homebrew 0.144.6 and bundled 0.151.0-alpha.7.2 failed the live
smoke check because the configured `gpt-6-astra` model requires a newer version.
Use a compatible CLI/runtime and prove the MCP read before activation. The example
path is not evidence of a working CLI. No user's model configuration was changed.

1. Copy `config.example.json` outside the repository. Set `state_dir` to a durable
   private directory (the temporary example path is only for testing). Keep that
   directory and database across restarts. Confirm the source repository paths.
2. Set up an internal Sentry integration for organization `ontola`. Subscribe to
   **issue** webhooks, including created and unresolved changes. Use a dedicated
   client secret and put the installation UUID in the configuration. Export the
   client secret as `SENTRY_WEBHOOK_SECRET` only for the receiver process. The
   receiver verifies HMAC SHA-256 over the original request bytes and checks the
   installation UUID. It accepts only error issues in the three allowed projects.
3. Run the receiver behind an HTTPS reverse proxy exposing only `/sentry`, with
   a 1 MiB request limit, short body/read timeouts, and connection/rate limits:

   ```sh
   python3 scripts/sentry-codex/bridge.py serve --config /path/to/config.json
   ```

   It binds `127.0.0.1:8791`. Configure Sentry's webhook URL as the proxy's HTTPS
   URL plus `/sentry`. Existing email and feedback alerts are not replaced.
   This receiver intentionally does not accept legacy `event_alert` payloads.
4. Run the worker separately, supervised by the host's service manager:

   ```sh
   python3 scripts/sentry-codex/bridge.py work --config /path/to/config.json
   python3 scripts/sentry-codex/bridge.py status --config /path/to/config.json
   ```

   `work --once` processes at most one queued issue. Worker output records draft
   URLs or blocked states; route that output into the host's operational alerts.
   No recurring Codex app automation is needed: the worker reacts to the queue.

## Behavior and recovery

The receiver persists only organization/project/issue identity, not request bodies
or telemetry. It responds after the durable enqueue, without waiting for Codex.
The SQLite primary key deduplicates concurrent deliveries and later regressions of
the same grouped Sentry issue. One worker runs across the whole suite at a time.

Every investigation clones **committed** code from both local repositories into a
new sibling layout, fetches their configured remote base branches, and leaves all
existing checkouts untouched. Browser issues target server `develop`; SaaS targets
SaaS `main`. Changes needed in both repositories stop for a coordinated review.

Codex fetches the issue through MCP, investigates, attempts a minimal fix, runs
relevant tests and returns a structured local report. The runner requires a fixed
result with passing reported tests and a patch before committing and creating a
**draft** PR. Test evidence here is agent-reported; normal CI and human review still
apply. The PR intentionally excludes raw Sentry telemetry. The local report keeps
the test commands and investigation details; the reviewer should inspect it.

A deterministic branch and an all-states GitHub PR lookup prevent duplicate PRs
even when an earlier PR was closed/merged. A pre-existing remote branch without a
PR blocks rather than overwriting it. No merge or deployment command exists.

Failures remain `blocked`; interrupted processes may leave `running`. These are
never automatically retried or expired because a remote publication may already
have succeeded. Stop the worker, check GitHub by deterministic branch and inspect
the retained run directory before manually reconciling the SQLite row. Retain the
dedup row permanently. Do not blindly delete the database to clear a failure.

## Validation and activation gates

```sh
python3 -m unittest discover -s scripts/sentry-codex -v
```

Before calling this live, verify a signed Sentry delivery from each project,
an actual Codex MCP read and investigation, a draft PR on the expected base, and
duplicate delivery producing no second run or PR. Check blocked-run notification
and restart recovery too. Do not send synthetic errors into production for this.

Official references:
- [Codex non-interactive mode](https://developers.openai.com/codex/noninteractive/)
- [Sentry webhook authentication and response requirements](https://docs.sentry.io/integrations/integration-platform/webhooks/)
- [Sentry issue payloads](https://docs.sentry.io/integrations/integration-platform/webhooks/issues/)
