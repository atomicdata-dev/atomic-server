# Vault recovery coverage

Based on develop `9be210d97` and SaaS main `36e2f5fc`.
Existing recovery fixes in #2130 and broader durability work in #1531 remain
separate; call out overlap in the PR. Vault stores graph state and file
references; file bytes remain in the S3 blob backend.

- [x] Reproduce and fix restore flush failure, partial import success,
      suspended recovery and recovered key epochs at the cheapest layer.
- [x] Exercise independent device databases, stale-device catch-up, concurrent
      edits and deletion through real Vault import/export.
- [x] Join restored file metadata with the separate persistent blob backend.
- [x] Add explicit Vault/Server browser transport coverage with fresh contexts
      and reload assertions, without duplicating UI-only tests.
- [x] Wire previously dormant real Vault and WASM tests into CI.
- [x] Run targeted regressions, integration coverage and complete lint;
      update TESTING_COVERAGE.md with exact evidence.

Automatic background pull, native lifecycle coverage, large-restore memory
bounds and arbitrary missing delta detection require separate implementation;
do not describe an explicit restore test as covering automatic catch-up.

2026-10-13 validation: all nine browser acceptance journeys passed on current
develop, with no retries or skips. Ordinary and invited-agent peer multiplayer
also passed with server graph access disabled. Full browser lint, type checks,
JS suites, WASM bindings, native Vault and real S3 recovery passed. Cold profile
recovery now merges restored Loro history with pending local edits; complete
server sync snapshots persist after a JSON-only lookup. Deletion tests cover
stale checkpoint races, checkpoint retention and deliberate later recreation.

- [x] Make the SaaS acceptance job required; add peer multiplayer to that job.
- [x] Review desktop and mobile recovery errors; keep technical causes out
      of the visible message. The focused missing/corrupt-object rerun passed.
- [x] Finish staged commit checks: recursive browser lint and workspace Clippy
      passed with hooks enabled.
- [x] Publish paired Server #2242 and update SaaS #217 on matching branch
      `claude/project-thread-2u2wpm`.
- [ ] Confirm exact-head CI succeeds. Local green does not close this item.

CI's previous run is queued on Mancave; a queued run is not a pass. Initial
Vault-only blob upload remains a separate implementation gap; the file drill
uses bytes previously uploaded to S3.
