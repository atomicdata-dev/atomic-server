# Sentry to Codex draft PRs

Status: local implementation validated; activation blocked.

- [x] Verify repositories and Sentry projects via GitHub and Sentry MCP.
- [x] Inspect existing alerts and local automations (no existing Codex trigger).
- [x] Implement authenticated webhook queue, isolated runner and deduplication.
- [x] Test routing, real local HTTP delivery/replay, concurrency, failure handling
      and mocked draft publication (9 tests).
- [ ] Configure an HTTPS receiver and Sentry internal integration.
- [ ] Prove a real Sentry delivery starts Codex and produces a reviewed draft PR.

Routing: `ontola/atomic-server` and `ontola/atomic-browser` go to
`ontola/atomic-server`, base `develop`. `ontola/atomic-saas` goes to
`ontola/atomic-saas`, base `main` (verified from GitHub, not the older SaaS
AGENTS reference to the server's `did` branch).

Sentry MCP confirmed all three projects. Existing high-priority email alerts:
3933571 (server), 3933568 (browser), 3933566 (SaaS), plus browser feedback
3955826. Preserve these. Subscribe an internal integration to issue creation
and unresolved changes; accept error categories only. Store each Sentry issue
once, including after failure or PR closure. A manual retry must reconcile the
deterministic branch with GitHub first. Never merge.

The available MCP catalog supports inspection, not integration/alert writes.
Activation needs an integration client secret and installation UUID plus a
reachable HTTPS receiver. No such receiver has been identified or deployed.

Read-only CLI smoke tests failed before model execution: both Homebrew Codex
0.144.6 and the app's bundled 0.151.0-alpha.7.2 return that the configured
`gpt-6-astra` model requires a newer version of Codex. The app task's Sentry MCP
works, but CLI-to-MCP execution is therefore not proven. A compatible CLI/runtime
is an additional activation gate. No model setting or installation was changed.
