# Drive sharing and hosting state

Status: in progress; not deployed.

- [x] Inspect the reported staging drive: sync connection active without confirmed Cloud Server hosting.
- [x] Replace the unconditional sharing refusal with the existing full local-copy verification and browser-only transition.
- [x] Preserve server routing when local history or attachment verification fails.
- [x] Gate seat messaging on the target drive subscription, never account-wide availability.
- [x] Add routing regression tests, including another drive enrollment and incomplete local copies.
- [ ] Supply authoritative per-drive editor usage from the backend. Current drive-scoped billing intentionally omits editors_used; the UI must not manufacture a number from account membership or direct ACLs.
- [ ] Trace why the historical drive retained remote routing without an enrollment. This change repairs it when sharing; it does not establish the original cause or proactively migrate all drives.
- [ ] Validate the full sharing flow with real browser persistence and attachments, then CI and staging acceptance.

The source connection must survive a failed completeness check. Vault existence or a cached root snapshot is not proof that all history and attachments are local.
