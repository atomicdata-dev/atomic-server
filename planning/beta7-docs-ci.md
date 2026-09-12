# Beta 7 documentation CI

- [x] Diagnose release CI 34701516468: installing mdbook-linkcheck without a lock resolves jiff 0.2.36, whose crate references missing documentation files.
- [x] Inspect the published crate to confirm broken include paths; linkcheck 0.7.7's published lock does not contain jiff.
- [x] Pin mdbook and mdbook-linkcheck and use their published locks in docs builds and cache benchmarks.
- [x] Fresh installation of mdbook 0.5.4 and mdbook-linkcheck 0.7.7 with --locked succeeded on Mancave; the current documentation built successfully.
- [ ] Merge after validation, verify release CI, and tag beta 7 at the corrected release commit.

The original release candidate d6320ccc0 must not be tagged after its failed CI. No beta tag has been published.
