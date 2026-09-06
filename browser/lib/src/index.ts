/**
 * # @tomic/lib Documentation
 *
 * Core typescript library for handling JSON-AD parsing, storing Atomic Data,
 * signing Commits, and more.
 *
 * [github repository](https://github.com/atomicdata-dev/atomic-data-browser)
 *
 * ## Features
 *
 * - Fetching Atomic Data
 * - Parsing JSON-AD
 * - Storing Atomic Data
 * - Data Validation
 * - Creating and signing {@link Commit}
 *
 * ## Usage
 *
 * You'll probably want to start by initializing a {@link Store}. Use methods
 * from the Store to load Resources. Use the {@link Resource} class to access,
 * edit and validate the data in a Resource. Use `Resource.save()` to save and
 * send edits to resources as Commits, or use the {@link Commit} class if you
 * need more control.
 *
 * ## Usage with react
 *
 * See `@tomic/react`, which provides various hooks for easy data usage.
 *
 * @module
 */

export * from './ontologies/core.js';
export * from './ontologies/collections.js';
export * from './ontologies/commits.js';
export * from './ontologies/dataBrowser.js';
export * from './ontologies/server.js';
export * from './ontologies/ai.js';
export * from './ontologies/canvas.js';
export * from './ontologies/forks.js';
export * from './ontologies/i18n.js';
export * from './canvas-strokes.js';
export * from './agent.js';
// Needed outside this package by the Cloud Vault client, which must convert an
// agent's base64 key into the raw seed before wrapping a drive key. Doing that
// conversion anywhere else risks the wrong representation being wrapped, which
// produces an envelope that cannot be opened with the real seed.
export { decodeB64, encodeB64 } from './base64.js';
export * from './authentication.js';
export * from './client.js';
export * from './genesis.js';
export * from './commit.js';
export * from './error.js';
export * from './withDeadline.js';
export * from './datatypes.js';
export * from './parse.js';
export * from './search.js';
export * from './resource.js';
export * from './forks.js';
export * from './store.js';
export * from './subject.js';
export * from './value.js';
export * from './urls.js';
export * from './truncate.js';
export * from './collection.js';
export * from './collectionBuilder.js';
export * from './ontology.js';
export * from './invites.js';
export * from './pairing.js';
export * from './loro-loader.js';
export * from './presence.js';
export * from './CryptoProvider.js';
export { ClientDbWorker } from './client-db.js';
export {
  attributionForVersion,
  mergeHistoryAttributions,
  parseHistoryAttribution,
} from './history-attribution.js';
export type { Attribution, HistoryAttribution } from './history-attribution.js';
export type { ClientDbQueryOpts, ClientDbQueryResult } from './client-db.js';
export {
  LocalOutbox,
  isTerminalCommitErrorMessage,
  isUnrecoverableCommitErrorMessage,
  isTerminalCommitError,
  isUnrecoverableCommitError,
  type OutboxEntry,
  type OutboxDrainContext,
} from './local-outbox.js';
export {
  perfMark,
  perfSpan,
  perfSnapshot,
  perfReset,
  type PerfEvent,
  type PerfSnapshot,
} from './perf-trace.js';
export * from './child-order.js';
