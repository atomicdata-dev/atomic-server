# External integration test fixtures

These neutral host-contract bundles are derived from test data in
`localthought/devonian@4ec37e2bc5c0a99d57150c530346fec9defde891`,
under `platform-lenses/atomic-integrations`. Provider names, origins, secret
slots, and identity prefixes use reserved test values. They let Rust regression
tests exercise sandbox and effect-journal behavior without copying provider
implementations into Atomic Server. Provider behavior is tested against the
currently pinned Devonian package by the external platform test suite.
