# Bounded live verification

Offline certification never enables live tests. A live run needs a dedicated
vendor test identity and a disposable repository or database shared only with
that identity. The personal Notion pilot is not a standing CI account.

Before a run, record provider, account owner, exact resource ID, bundle hash,
Atomic connection and approver. Issue a short-lived credential restricted to
that resource; keep it in the host secret store, never fixtures or reports.
Use a new Atomic drive and unique run prefix for every created record.

For the first automated canary, use this bounded sequence:

1. Verify the current full offline report matches the candidate bundle.
2. Inspect only the allowlisted repository/data source. Abort on unexpected
   schema, permissions, existing run prefix or an active background schedule.
3. Create one provider row, import it, edit one supported field in Atomic,
   then edit it in the provider and pull it back. Assert exact values each way.
4. Create one Atomic row and push it. Repeat the sync twice; assert exactly two
   remote records with the run prefix and stable bindings.
5. Stop after ten minutes or twenty provider mutations, whichever comes first.
   A timeout is a failure, never a successful or skipped certificate.
6. Close/archive only the two records recorded in this run's creation receipts.
   Never clean up by broad name search. Retain IDs when cleanup fails, and
   report failure so the owner can recover them. Revoke the run credential.

Keep polling disabled for this manual canary. A background variant needs an
explicitly authorized test window, durable expiry enforced by the host, and
verified schedule shutdown even when the runner crashes. A client-side timeout
alone does not bound a persistent server schedule.

Evidence must record assertions, candidate hash, provider API version, start/end
times and cleanup outcome without credentials or private row contents. A failed
assertion or incomplete cleanup prevents promotion. Provider errors should retain
status/request IDs where safe; never dump authentication headers.

Implementation status: this is the run contract, not an automated live runner.
Dedicated accounts, host-enforced expiry and live adapters remain to implement.
The existing GitHub live test is tied to its specific sandbox; Notion's
`atomic.live.test.ts` uses authored HTTP replies and is not vendor-live evidence.
