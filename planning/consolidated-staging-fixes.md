# Consolidated staging fixes

- [x] Verify all five PR commits are included in the two repository heads.
- [x] Fix fork regression lint errors and Cargo registry extraction race.
- [x] Fix portable OpenSSL builds and pnpm cache setup in SaaS.
- [x] Run local lint and relevant checks; push paired branches.
- [x] Update combined PRs and close superseded PRs.
- [ ] Verify CI and address remaining failures.

Combined PRs: atomic-server #1397 and atomic-saas #60. Superseded #1395, #1400 and SaaS #59 are closed.

Local validation: 399 client tests, 800 app tests, 71 server tests, full browser lint, app typecheck, portal lint/build pass.

CI runs 34353039272 (server) and 34353048110 (SaaS): SaaS control-plane, managed-node, coverage and real protocol E2E passed; portal E2E and server pipeline still running. No local Dagger execution.
