# Bank statements (MT940)

Open Integrations → Bank statements → Set up connection. Choose an MT940 file,
preview, and approve. Reopen the installed Bank statements importer for later
files. A Bank transactions table lives beneath the importer; rows live beneath
that table. Shared banking terms live in the drive ontology.

bunq exports: bank account → Settings → Export statement → MT940.
https://help.bunq.com/en-ie/articles/how-do-i-export-a-bank-statement

## Architecture

`plugin.ts` bundles the parser and mapping into `plugin.js`. File acquisition is
UI code. Parsing first runs in an isolated browser Worker; proposal generation
runs in the server QuickJS/WASM host, which supplies scoped query/read access.
No network operations or secrets are declared. File contents are runtime input,
not plugin source. Proposals and approved transactions contain financial data
and are handled by the user's AtomicServer; they are not sent to an LLM.

Amounts are exact signed decimal **strings**, not floating point numbers.
Opening/closing balances are reconciled with integer arithmetic (up to five
fractional digits). Dates have no inferred time zone. Original :86: descriptions
are retained verbatim, including bank-specific structured codes. Bank account
identifiers are preserved, not assumed to be IBANs. Schema term descriptions
record these meanings; this is not a frozen or ISO 20022-certified schema.

Bank references identify transactions within an account and currency. A changed
reference payload blocks the import. Without references, statement metadata and
line position identify records; content fingerprints block ambiguous overlap
with earlier exports. Identical legitimate rows within a statement are retained.
Import is append-only: local edits are not overwritten. Deleted imports may be
recreated on another import. Native `localId` identities are unique within the destination on one AtomicServer: a
concurrent duplicate create is rejected and must be previewed again. The shared
`importBaseline` records source values and protects local edits. Independent
offline peers still need collision resolution after synchronization.

## Supported scope and gaps

- Up to 500 entries / 512 KB; UTF-8 or Windows-1252 text.
- :20:, :21:, :25:, :28:/28C:, :60F:/60M:, :61:, :86:, :62F:/62M:, :64:, :65:.
- Credit/debit reversals, optional booking dates (value date fallback), multiple
  statements/accounts, multiline transaction narratives.
- Unsupported fields, missing balances and reconciliation failures block import.
- JSON-shaped narratives are rejected because legacy storage reinterprets those
  strings. This needs a general text-preservation fix before enabling them.
- No live bank access, payments, CSV/PDF, counterparty extraction or categorization.
- Amount columns cannot yet use numeric table aggregation; an exact decimal
  datatype/table formatter is a follow-up.
- No real bunq statement supplied yet. Synthetic fixtures test format behavior;
  they do not establish compatibility with every bank's dialect.
- The default importer, table and view reuse durable setup identities after lost
  responses. Shared ontology/schema creation still needs resumable installation.
- File importer metadata/UI dispatch is currently MT940-specific; generalize this
  when adding the next file-based plugin. It uses the same proposal runtime.

Reference: https://bankrec.westpac.com.au/docs/statements/mt940/

Tests: `./browser/node_modules/.bin/vitest run --config integrations/mt940/vitest.config.ts`
Bundle: `./browser/node_modules/.bin/esbuild integrations/mt940/plugin.ts --bundle --format=esm --platform=neutral --target=es2022 > integrations/mt940/plugin.js`
Browser: `browser/e2e/tests/mt940.spec.ts` (synthetic file, real runtime/persistence).
