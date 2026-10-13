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
export * from './ontologies/notifications.js';
export * from './ontologies/conversations.js';
export * from './ontologies/i18n.js';
export * from './ontologies/forms.js';
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
export * from './pkarr.js';
export * from './datatypes.js';
export * from './class-constraints.js';
export * from './effective-constraint.js';
export {
  planOntology,
  slugify,
  type ConstraintInput,
  type OntologyClassInput,
  type OntologyInput,
  type OntologyPlan,
  type OntologyPropertyInput,
} from './ontology-input.js';
export {
  JSON_SCHEMA_DIALECT,
  ontologyFromJsonSchema,
  ontologyToJsonSchema,
  propertyJsonSchema,
  type JsonSchemaImportOptions,
} from './schema-json-schema.js';
export { isJsonSchema, ontologyFromSchemaFile } from './schema-file.js';
export {
  assertLockfileMatches,
  checkLockfile,
  lockfileFromEnsured,
  lockfileFromInput,
  parseLockfile,
  serializeLockfile,
  type Lockfile,
} from './schema-lockfile.js';
export * from './safeHref.js';
export { EventManager } from './EventManager.js';
export * from './parse.js';
export * from './search.js';
export * from './resource.js';
export * from './chat-log.js';
export * from './forks.js';
export * from './store.js';
export * from './property-identity.js';
export * from './lens.js';
export * from './lens-ensure.js';
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
export * from './page-request-signal.js';
export * from './presence.js';
export * from './json-ad-compact.js';
export * from './subject-refs.js';
export * from './standard-class-alias.js';
export * from './class-schema.js';
export * from './assistant-tools.js';
export * from './CryptoProvider.js';
export { ClientDbWorker, STORAGE_BLOCKED_ERROR_NAME } from './client-db.js';
export {
  getIndexMigration,
  subscribeIndexMigration,
  type IndexMigrationProgress,
} from './client-db-migration.js';
export {
  attributionForVersion,
  mergeHistoryAttributions,
  parseHistoryAttribution,
} from './history-attribution.js';
export type { Attribution, HistoryAttribution } from './history-attribution.js';
export type {
  ClientDbOutboxWrite,
  ClientDbQueryOpts,
  ClientDbQueryResult,
} from './client-db.js';
export {
  LocalOutbox,
  isTerminalCommitErrorMessage,
  isUnrecoverableCommitErrorMessage,
  isTerminalCommitError,
  isUnrecoverableCommitError,
  isBenignTerminalCommitError,
  isNotEnrolledMessage,
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

export { WebRtcPeer } from './webrtc-peer.js';
export { WebRtcTransport } from './webrtc-transport.js';

export {
  BrowserPeerSync,
  randomPeerToken,
  type BrowserPeerOptions,
} from './browser-peer-sync.js';

export { decodeBrowserInvite } from './browser-peer-invite.js';

export * from './scheduled-save.js';
export {
  hasBlockingProblems,
  LOCAL_REF_PREFIX,
  parseVerdict,
  type CreateIntent,
  type DestroyIntent,
  type Intent,
  type ParseVerdictOptions,
  type Problem,
  type ProblemSeverity,
  type RemoveIntent,
  type SetIntent,
  type Verdict,
} from './plugin-run.js';
export {
  applyDeterministicGlobals,
  denyAmbientGlobals,
  invokeRun,
  DENIED_GLOBALS,
  type InvokeOptions,
  type InvokeResult,
  type PluginModule,
  type RunInput,
  type RunTrigger,
  type TriggerKind,
} from './plugin-sandbox.js';
export {
  runPlugin,
  type PluginRunOutcome,
  type PluginRunRequest,
  type PluginRunResponse,
  type PluginWorkerFactory,
  type PluginWorkerLike,
  type RunPluginOptions,
} from './plugin-runner.js';
export {
  planVerdict,
  planHostFromStore,
  type PlanHost,
  type PlanStore,
  type PlannedChange,
  type PlannedProperty,
  type RunPlan,
} from './plugin-plan.js';
export {
  applyPlan,
  applyHostFromStore,
  type ApplyStore,
  type ApplyHost,
  type ApplyOptions,
  type ApplyReport,
  type ChangeOutcome,
  type ChangeStatus,
  type CreateRequest,
} from './plugin-apply.js';
export {
  ensureOntology,
  ensureSchema,
  findSchema,
  type ClassSpec,
  type EnsureOntologyOptions,
  type EnsuredOntology,
  type EnsuredSchema,
  type PropertySpec,
  type SchemaSpec,
  type SchemaStore,
} from './plugin-schema.js';
export {
  recordRun,
  runStatus,
  pluginSchema,
  type RecordRunOptions,
  type RunStatus,
} from './plugin-log.js';
export * from './agent-grants.js';
export * from './issue-access-agent.js';
export {
  createApp,
  describeApp,
  updateApp,
  type AppDescription,
  type CreateAppOptions,
  type CreatedApp,
} from './plugin-app.js';
export {
  catalogAppProperties,
  catalogAppSchema,
  catalogAppState,
  compareVersions,
  fetchCatalogAppModule,
  installCatalogApp,
  parseCatalogApp,
  readInstalledCatalogApps,
  resolveModuleUrl,
  subresourceIntegrity,
  updateCatalogApp,
  type CatalogApp,
  type InstalledCatalogApp,
} from './catalog-app.js';
export {
  parseManifest,
  validateManifest,
  type CapabilityName,
  type DeclaredAction,
  type DeclaredCapability,
  type DeclaredEntrypoints,
  type DeclaredNetwork,
  type DeclaredOperation,
  secretsMentionedIn,
  originsMentionedIn,
  type DeclaredSecret,
  type DeclaredConfig,
  type DeclaredConfigField,
  type DeclaredAccept,
  type DeclaredDestination,
  type DeclaredDestinationTable,
  DEFAULT_ACCEPT_MAX_BYTES,
  ACCEPT_MAX_BYTES_CEILING,
  type ManifestRuntime,
  type ManifestWorld,
  type PluginManifest,
  type PluginManifestV2,
} from './plugin-manifest.js';
export {
  pluginConfigFor,
  pluginConfigProblems,
  type StoredPluginConfig,
} from './plugin-config.js';
export { describePlugin } from './plugin-runner.js';

export {
  reconcileRecord,
  acknowledgedBaseline,
  type SyncRecord,
  type SyncValue,
  type SyncConflict,
  type SyncDecision,
} from './plugin-reconcile.js';

export {
  publishPluginRelease,
  pinPluginRelease,
  readExternalOperation,
  approveExternalIntent,
  readConnectionState,
  readConnectionSubjects,
  checkpointConnection,
  type ConnectionState,
  type ConnectionCheckpoint,
  inspectExternalOperation,
  confirmExternalOperation,
  type ExternalOperation,
  type ExternalOperationStatus,
  type PluginRelease,
  type ExternalIntent,
  type ExternalReceipt,
  type PluginTarget,
  previewPluginSync,
  applyPluginSync,
  getPluginSync,
  type PluginSyncSession,
} from './plugin-connection.js';

export {
  pluginSyncSchedule,
  type PluginSyncSchedule,
} from './plugin-connection.js';
export {
  installRelease,
  updateInstallationRelease,
  publishZipRelease,
  readInstallationReview,
  grantsFor,
  installationIdentifier,
  DEFAULT_INSTALLATION_NAMESPACE,
  RUNTIME_JS,
  type InstallationStatus,
  type InstallationReview,
  type InstallReleaseOptions,
  type UpdateReleaseOptions,
  type PublishedRelease,
  type ReleaseReference,
  type ReviewCapability,
} from './plugin-install.js';
export * from './integration-actions.js';

export { taskSchema } from './task-schema.js';

export { timeTrackingSchema } from './time-tracking-schema.js';

export { executeServerPlugin } from './plugin-server.js';
export {
  importRecords,
  resolveImportConflict,
  claimImportIdentity,
  IMPORT_BASELINE,
  IMPORT_LOCAL_ID,
  type ImportRecord,
  type ImportHost,
} from './import-records.js';

export { resumableInstallation } from './resumable-installation.js';

export * from './import-resolution.js';

export * from './import-reference-review.js';

export {
  destinationTablesFor,
  provisionDestination,
  type DestinationConfig,
  type DestinationTable,
} from './plugin-destination.js';
export { pluginWorkspace, workspaceConnections } from './plugin-workspace.js';
export type { WorkspaceConnection } from './plugin-workspace.js';

export {
  calendarFields,
  isCalendarDate,
  isAllDayOnDate,
  nextCalendarDate,
  matchesCalendarField,
  calendarRecurrenceShortname,
} from './calendar-date.js';

// The expansion functions live in `@tomic/lib/calendar-recurrence.js`: they
// pull in the Temporal polyfill (~120 kB), which most apps never need.
export type {
  CalendarTime,
  CalendarEvent,
  CalendarRecord,
  CalendarOccurrence,
} from './calendar-recurrence.js';

export {
  parseSetupDeclaration,
  validateSetupArguments,
} from './plugin-setup.js';
export type {
  SetupDeclaration,
  SetupField,
  SetupArguments,
} from './plugin-setup.js';

export {
  appPackageSchema,
  parseAppPackage,
  readAppPackage,
  prepareAppPackageImport,
} from './app-package.js';
export type { AppPackage } from './app-package.js';
