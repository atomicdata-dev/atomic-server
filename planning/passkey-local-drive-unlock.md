# App sign-out and local drive unlock

- [x] Reproduce portal Open after completed app sign-out in the same browser.
- [x] Route LOCAL_ONLY_NOT_FOUND_MESSAGE through the existing unlock flow even when the app origin has a configured node.
- [x] Avoid rendering the transport error while the unlock redirect is pending.
- [x] Unit regression and TypeScript check.
- [x] Paired real-service browser regression: popup handoff, then virtual-passkey unlock on its original CDP target, original drive title restored.
- [ ] Investigate original-tab direct navigation after sign-out: it can surface a different NotFound error (DID not found locally) instead of the local-only transport error. A speculative local-only guard did not resolve it and was removed.
- [ ] Verify the complete new-tab unlock with a physical passkey provider.
- [ ] Review and deploy.

App sign-out clears the app identity and session database keys. A portal session does not unlock the encrypted app database. The fix reuses the existing unlock flow; it does not create a replacement drive or change Cloud Server routing.
