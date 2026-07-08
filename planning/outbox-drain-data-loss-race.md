# Outbox drain can silently drop a write (data loss)

> Status: confirmed bug, 2026-07-08. Correctness. Not yet root-caused.
>
> Found while writing `browser/e2e/tests/forms.spec.ts` (Forms builder
> Phase 2). Reproduced independently of Forms and of React — this is a
> `@tomic/lib` core save/sync issue. Related to, but distinct from,
> [`unify-resource-dirty-signals.md`](./unify-resource-dirty-signals.md)
> (that doc is about fragmented UI "saving" state; this is silent data
> loss with the client believing the save succeeded).

## Problem

A `resource.set(prop, value)` followed by `await resource.save()` can
report `'persisted'` (success), and the resource's local in-memory
value is correct — but a fresh server-side fetch (bypassing all local
caches) sometimes still returns the **old** value. The write is silently
dropped: no error, no toast, no blocked-outbox entry, `pendingDirtyCount`
correctly drains to `0`.

It is non-deterministic: the exact same code, on the same resource, run
again, can persist correctly. This points to a timing race rather than a
deterministic logic bug.

## Reproduction

Confirmed via direct library calls in a Playwright test, no React
involved:

```ts
const r = window.store.resources.get(subject)!;
await r.set(prop, { options: ['X', 'Y', 'Z'] });
const saveResult = await r.save();               // => 'persisted'
const fresh = await window.store.fetchResourceFromServer(subject, {
  setLoading: true,                               // force a real round trip
});
fresh.get(prop);                                  // sometimes still the OLD value
```

Observed on a `formFieldOptions` (JSON-datatype) property of a `FormField`
resource created moments earlier in the same session (several prior
`set`+`save` cycles on sibling/parent resources had already happened —
this is not a fresh, untouched resource).

Also reproduced with `core.properties.name` on the same resource in the
same run, so it is **not** specific to the JSON datatype or to
`formFieldOptions`'s own (currently network-unresolvable, see below)
Property definition — though that may still be a contributing factor in
some runs.

## Suspected root cause

`local-outbox.ts` uses a "sign-at-drain" model: dirty subjects are
tracked as bits, and the Loro delta is exported + signed + POSTed at
drain time, not at `set()` time. Hypothesis:

1. Drain starts for subject S, exports delta at version V1.
2. While the POST is in flight, a new local edit lands on S (version
   V2), and `markDirty(S)` is called again.
3. The in-flight drain's POST completes successfully for V1.
4. The drain-completion handler clears S's dirty bit unconditionally,
   instead of checking whether the resource's version advanced past V1
   since the export was taken (i.e. whether another edit is still
   unexported).
5. The V2 edit is now silently gone from the outbox's perspective —
   `pendingDirtyCount` reads `0`, nothing is blocked, but the server
   never received V2.

This is a guess from reading `local-outbox.ts`'s drain loop shape, not
a confirmed trace — the actual fix needs to instrument the drain
loop (export version, POST completion, dirty-clear) and catch the race
live, e.g. with an artificial delay injected between export and POST in
a unit test.

A secondary, independent contributor worth ruling out first:
`Resource.set()`'s validation path does `await this.store.getProperty(prop)`
before writing to Loro. For brand-new ontology properties (like
`forms.properties.formFieldOptions`), this fetch currently fails against
the real `atomicdata.dev` (see `Resource.set`'s catch-and-warn branch,
`resource.ts` ~line 2838) rather than resolving against the locally
connected server — this fetch's latency/timing may be what widens the
race window in some runs. That resolution bug (client validating new
built-in ontology properties against production `atomicdata.dev` instead
of the connected server) is worth fixing on its own regardless of this
data-loss race — see "Related, separate issue" below.

## Related, separate issue: property validation hits production, not the connected server

Independent of the race above: `Resource.set()`'s validation fetch for a
brand-new, not-yet-upstreamed default-ontology property (e.g. anything
in a freshly added `lib/defaults/*.json` file) resolves against the
literal `https://atomicdata.dev/...` URL — the real production site —
instead of asking the currently-connected local/self-hosted server for
it. This means **any** newly added built-in Property will always fail
this validation fetch in every environment until it's deployed to
production atomicdata.dev, which is backwards for local dev and
self-hosted servers. Worth its own investigation into how
`store.getProperty()` decides where to fetch an absolute-URL subject
from.

## Why this matters

Silent data loss is worse than a visible error — the user (and any
caller checking `save()`'s return value) has no signal anything went
wrong. `browser/e2e/tests/forms.spec.ts`'s "create a form, add every
field type, and persist across reload" test asserts the radio field's
edited options and the Form's publish state survive a reload; per
explicit product decision (2026-07-08) that assertion was **kept
strict** rather than softened, specifically so this test keeps failing
until the race is fixed. Expect it to be flaky in CI until then — that
flakiness is the intended signal, not noise to suppress.

## Concrete next steps

1. Add focused unit/integration tests in `browser/lib` that drive
   `LocalOutbox`'s drain loop with an injected delay between "export
   delta" and "POST", firing a concurrent `markDirty` mid-flight, to
   deterministically reproduce the race outside a flaky e2e test.
2. Once reproduced deterministically, fix the drain-completion path to
   only clear the dirty bit if the exported version is still the
   resource's current version (or re-export/re-drain if it advanced).
3. Separately investigate `store.getProperty()`'s subject-resolution
   logic for locally-defined (not-yet-production) default ontology
   properties.
4. Once fixed, `forms.spec.ts` should pass consistently — treat its
   continued flakiness as the regression signal for this bug.
