# Plugin Secrets and Host-Side Fetch

## Status

Proposal (2026-08-20). The gating dependency for
[`plugins.md`](./plugins.md) A3, and named there and in
[`importers.md`](./importers.md) as designed nowhere. Not started.

## Why

Four things on the roadmap are waiting on this and nothing else:

- the HTTP action a plugin needs to reach anything outside the drive;
- email, which should be an HTTP call to a provider rather than an SMTP
  client in atomic-server;
- token-based importers — Notion's API sends no CORS headers, so the browser
  cannot fetch it at all;
- every scheduled connector in
  [`personal-information-suite.md`](./personal-information-suite.md).

All four need the same two things: somewhere to keep a credential that is not
the resource graph, and a way to spend it without the plugin ever seeing it.

## What Exists Today

Three findings from the current WASM plugin runtime, all load-bearing for this
design:

**Secrets already live outside the graph.** `PluginMeta`
(`lib/src/db/plugin_meta.rs`) stores a plugin's `agent_secret` in its own redb
table keyed by `(drive, namespace, name)` — not as a resource. It is therefore
never committed, never synced, never indexed. That is the right shape and this
design extends it rather than inventing a second one.

**Network access is all or nothing.** `PermissionType::Network` maps to
`builder.inherit_network()` in `server/src/plugins/wasm.rs`. A plugin that
declares it gets the host's entire network: loopback, the private ranges, and
any cloud instance-metadata endpoint the host can reach. There is no origin
allowlist, and `plugins.md`'s manifest already assumes `network.origins`.

**`get_resource` is a second egress.** For a subject outside the server's own
URL the host calls `db.fetch_resource`, gated on the same binary Network
permission. Any allowlist that only covers a new `http-request` import would
leave this path open.

## The Threat

Not "the plugin author is hostile" — the interesting case is duller and more
likely. A plugin is written by an LLM, from a prompt, over data the user did
not audit. It will contain mistakes, and its input may contain text an attacker
chose. The properties worth buying:

- A credential cannot end up in a commit, a sync frame, a search index, a log
  line, or an LLM's context, because it is never in any of them.
- A plugin cannot read a credential it is allowed to *use*, so a mistake that
  serializes its own config cannot leak one.
- A plugin cannot reach the host's internal network, whatever URL it computes.
- A user can see which origins a plugin may reach before approving it, and can
  revoke that later.

## Design

### Secrets are host state, not resources

```text
PluginSecret          keyed by (drive, plugin subject, name)
  value               plaintext, at rest under the same protection as agent_secret
  origins             origins this secret may be sent to
  createdAt, lastUsedAt
```

Stored in a redb table beside `PluginMeta`. **No endpoint returns a value** —
not to the browser, not to the plugin, not to an admin UI. Writes are
create-or-replace; reads are for the host at invoke time only. Deleting the
plugin deletes its secrets.

`lastUsedAt` exists so a user can answer "is this still in use" before
revoking, which is the question that otherwise keeps dead credentials alive.

### A plugin gets a handle, never a value

The guest sees `secret:<name>` and can pass it where a credential goes:

```ts
const res = await ctx.http({
  url: 'https://api.notion.com/v1/databases/…',
  headers: { Authorization: 'Bearer secret:notion' },
});
```

The host substitutes at the boundary. A plugin that logs its config, returns it
in a verdict, or embeds it in an intent leaks the string `secret:notion`.

Substitution happens **only** in header values and only for a secret whose
`origins` include the request's origin. A handle in a URL, a body, or a query
parameter is not substituted — it is an error naming the handle, because a
credential in a URL ends up in logs and referrers by design, and silently
sending it there would be the worst kind of helpful.

### One egress, with guards

Every outbound request — the new `http-request` import *and* the existing
`get_resource` fetch for foreign subjects — goes through one function:

1. **Origin allowlist.** The manifest's `network.origins`, approved at install
   and shown in the install dialog. No wildcard hosts; `*.example.com` is
   spelled out or not allowed.
2. **Resolve, then check.** DNS-resolve the host and reject loopback,
   link-local, private, unique-local, and unspecified addresses. Checking the
   hostname is not enough: a name that resolves to `169.254.169.254` is the
   whole attack.
3. **Re-check after every redirect**, against both the allowlist and the
   address rules. Cap the chain; drop credential headers on a cross-origin
   redirect.
4. **Cap** response size, total time, and concurrent requests per plugin.
5. **Redact.** Log the handle name, never the substituted value. Errors
   returned to the plugin carry status and origin, not response bodies from
   another origin's error page.

This replaces `inherit_network()`. A plugin never gets ambient sockets, so
there is no second path to guard.

### Placement follows the secret

A browser cannot hold a secret the plugin's own page cannot read, and cannot
reach a no-CORS API. So:

> **A run that needs a secret, or an origin the browser cannot reach, is
> placed server-side.**

This is a rule, not an option, and it is derived from the manifest exactly like
the other placement rules in [`plugins.md`](./plugins.md). It also means A3 is
only fully useful once A4 (the job queue and server-side placement) exists —
but the storage, the allowlist, and the egress guards are worth having first,
because the existing WASM runtime needs them today.

### Setting a secret

A drive authority pastes a value into a dialog listing the origins it will be
sent to. The value goes straight to a write-only endpoint. It is never put in a
resource, so it never enters the outbox, and the LLM assistant has no tool that
can read or set one — a plugin that "needs" a credential in its source is an
authoring mistake, and the assistant should say so rather than route around it.

## What This Changes

- `lib/src/db/plugin_meta.rs` — a `PluginSecret` record and table beside
  `PluginMeta`.
- `lib/src/db/plugin_meta.rs` — `PluginManifest.permissions` gains structured
  `network.origins`; `PermissionType::Network` is removed rather than kept as
  a synonym for "everything", so no existing manifest silently keeps ambient
  access.
- `server/src/plugins/wasm.rs` — drop `inherit_network()`; add the guarded
  egress; route `get_resource`'s foreign-subject branch through it.
- A write-only secrets endpoint plus the install-dialog origin list.
- The `run` contract gains `ctx.http`, host-side only, absent in the browser
  placement so a plugin that calls it there fails at authoring time with the
  message the sandbox already gives for `fetch`.

## Rollout

1. **Egress guard + origin allowlist**, replacing `inherit_network()`. No new
   features; closes the current hole and is independently shippable.
2. **Secret storage + write-only endpoint + install dialog.**
3. **`ctx.http` with handle substitution**, server placement only.
4. **First consumer**: a Notion importer, which is the case that motivated all
   of it, and the one that proves the token path end to end.

## Decisions

- Secrets are host state keyed by `(drive, plugin, name)`, never resources.
  They cannot be synced or committed because there is nothing to sync.
- Plugins receive handles. No endpoint returns a value, to anyone.
- Substitution is header-only, origin-scoped. A handle anywhere else is an
  error, not a best-effort substitution.
- One egress function for every outbound request, including the existing
  foreign-subject fetch.
- Allowlists are exact origins, checked after DNS resolution and again after
  every redirect.
- `PermissionType::Network` is removed, not aliased. Ambient network access
  stops being expressible.
- A run needing a secret is placed server-side. Not configurable.

## Open Questions

- Encryption at rest: `agent_secret` is stored plaintext today. Do plugin
  secrets inherit that, or does this become the forcing function for the
  key hierarchy in [`encryption.md`](./encryption.md)?
- Does a secret belong to a plugin, or to a drive with plugins granted use of
  it? Per-plugin is simpler and revocation is obvious; per-drive avoids pasting
  the same token into four importers.
- Should `lastUsedAt` be a counter and a timestamp? "Used 0 times in 90 days"
  is a better revocation prompt than a date alone.
- Rate limiting is per plugin here. Per origin as well, so one plugin cannot
  get a drive's token throttled by a provider?
