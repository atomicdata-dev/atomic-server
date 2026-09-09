# Production readiness follow-up

- [x] Revalidate the account after Vault export and before subsequent API writes.
- [x] Treat an expired session as cancelled background work; retain other warnings.
- [x] Add focused regression coverage (78 Vault tests pass); typecheck and focused lint pass.
- [x] Paired local SaaS suite: 49 passed, 3 opt-in skipped; separate two-node mock billing/hosting test passed.
- [ ] Finish paired CI.
- [ ] Verify real Stripe sandbox checkout (see sibling SaaS PAYMENT_TESTING.md).
- [ ] Complete operational restore and monitoring gates in the SaaS runbooks.

Production has not been promoted. Full-suite browser logs remain strict about
unexpected warnings/errors. The SaaS older-tab test only accepts individually
verified HTTP 401 responses after explicit logout, with exact diagnostic counts.
