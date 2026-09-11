# Fork banner after refresh

- [x] Trace originalSubject through local, HTTP, and WebSocket collection paths.
- [x] Reproduce the incorrect banner with query candidates containing normal drive resources (two failing component tests before the fix).
- [x] Verify Fork type and originalSubject before counting or rendering proposals.
- [x] Validate: three component tests, five Chromium fork E2E tests, typecheck and frontend build pass; catalogs unchanged.
- [ ] Reproduce why Safari's query returned unrelated resources. Local HTTP, WS and OPFS queries return the correct empty set. Playwright WebKit fails OPFS initialization before dev-drive setup. No query-engine cause has been confirmed.

The UI safeguard is in PR #1397. Do not describe this as a verified fix to the underlying query engine or as Safari acceptance testing.
