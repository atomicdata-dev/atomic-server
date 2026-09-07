# Sentry and feedback readiness

Production remains on hold. Updated 2026-09-07.

- [x] Audit browser initialization and sidebar.
- [x] Report React caught, uncaught and recoverable errors using React 19 root callbacks.
- [x] Add sidebar feedback with optional reply email, validation, retained text on delivery failure, and info@ontola.io fallback.
- [x] Six unit tests pass; Playwright verifies failed delivery and successful retry.
- [x] A real sidebar submission reached the atomic-browser Sentry project: event `7052fda7352d4e6ea816061e8fd4f056`, issue ATOMIC-BROWSER-2 / 7717047321. The synthetic “please disregard” message was classified as spam; verified in the Spam folder, not mistaken for a missing event.
- [x] Synthetic unhandled error received: ATOMIC-BROWSER-3 / 7717047333. Environment staging and release present.
- [x] A caught React boundary error was accepted: `dc61c11c002847f6a92f0878ccf9a3ae`. Test substituted only the App module while exercising the real index.tsx root handlers.
- [x] Already-deployed app.staging.atomicserver.eu accepted a synthetic browser error: `5d989d731f294dde8e10a7e1b8167f55`, release atomic-data-browser@0.41.0-beta.5+1e5e130, environment staging.
- [x] Created and verified “Atomic browser feedback” alert 3955826: new issue, category feedback, atomic-browser project, all environments, notify Joep Meindertsma on every trigger. Existing high-priority error email alerts cover atomic-browser, atomic-server and atomic-saas. Browser error alert triggered during verification.
- [x] Confirm notification email arrives in joep@ontola.io: Gmail showed the feedback-rule test notification ATOMIC-BROWSER-4 at 14:44 CEST and real uncaught/caught error notifications ATOMIC-BROWSER-3 and ATOMIC-BROWSER-5 at 14:38 and 14:45. The first synthetic feedback itself was spam-filtered, so deployed non-spam feedback still needs an end-to-end check.
- [ ] Ship the sidebar and React handler changes to staging, then recheck feedback from the deployed app.
- [ ] Configure private source-map upload and verify a symbolicated error from a deployed minified bundle. The browser only produces maps with SOURCEMAP=1; the SaaS deployment does not set it and neither repository has a SENTRY_AUTH_TOKEN secret. Do not publicly expose private portal source maps as a workaround.
- [ ] Verify backend/managed-node synthetic reporting independently; browser acceptance does not establish backend coverage.

The DSN is a public ingestion key, not authorization to read projects or upload source maps. A Sentry upload credential needs explicit setup. No production deploy was requested or performed.

Known baseline full typecheck failures remain in upgradeDocument.ts (two instanceof errors) and loro-loader.ts (unused ts-expect-error); changed files typecheck cleanly.

Links: [feedback report](https://ontola.sentry.io/issues/feedback/?feedbackSlug=atomic-browser%3A7717047321&mailbox=ignored), [error](https://ontola.sentry.io/issues/7717047333/), [feedback alert](https://ontola.sentry.io/monitors/alerts/3955826/).

CI initially caught explicit label association and spacing lint failures. Fixed both; full data-browser lint/format check, six unit tests and the feedback Playwright scenario pass locally afterward.
