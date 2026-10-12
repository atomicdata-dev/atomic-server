import { commits } from './ontologies/commits.js';
import { core } from './ontologies/core.js';
import { forms } from './ontologies/forms.js';
import { server } from './ontologies/server.js';
import { GENESIS } from './urls.js';

/**
 * The one place that says which properties the client never authors.
 *
 * Three call sites used to carry their own copy of this list and had drifted
 * apart (`Resource.rebuildCacheFromLoro`, `Resource.merge`, the store's OPFS
 * cold-load guard). They are now the two sets below; one is derived from the
 * other, so a property added here reaches every consumer.
 */

/**
 * Properties the SERVER derives for a resource and that the client must never
 * write into its CRDT.
 *
 * They all have another source of truth: `lastCommit` is commit metadata,
 * `createdAt` and `createdBy` come from the genesis certificate (see
 * `Resource.getCreatedBy`). Writing one into Loro produces a LOCAL operation,
 * and a local operation means a dirty subject and a commit — for a value the
 * client never authored. On a resource you may write that is a redundant
 * commit per hydration; on one you may only READ, the server refuses it
 * forever, which is how an invitee who had written nothing ended up with a
 * blocked outbox entry and a permanent "changes pending".
 *
 * They stay in the read cache, so `resource.get()` and JSON-AD round-trips are
 * unaffected — which is why {@link SERVER_MANAGED_PROPS} includes them, and why
 * `Resource.merge` copies exactly this set from the incoming resource's cache:
 * a CRDT merge cannot carry a value that is in no Loro doc, so the incoming
 * (server-fresh) copy has to be taken by hand.
 */
export const DERIVED_BY_SERVER: ReadonlySet<string> = new Set<string>([
  commits.properties.lastCommit,
  commits.properties.createdAt,
  server.properties.createdBy,
  // Class-extender output: a summary only the server may compute. Letting it
  // into the Loro doc would turn it into a local op that a later save signs
  // into a commit, persisting a stale copy.
  forms.properties.formSubmissionSummary,
]);

/** True for a propval the server derives — see {@link DERIVED_BY_SERVER}. */
export const isDerivedByServer = (prop: string): boolean =>
  DERIVED_BY_SERVER.has(prop);

/**
 * Everything in {@link DERIVED_BY_SERVER} plus the genesis-immutable
 * properties: set once at creation (by the client, into Loro) and never
 * re-encoded into a later delta, so a cache rebuilt from a delta-only doc would
 * otherwise drop them. `Resource.rebuildCacheFromLoro` preserves these from the
 * previous cache.
 *
 * A resource that has ONLY these — no class, no user content — is a skeleton,
 * not a renderable resource. The store's OPFS cold-load guard
 * (`Store.hasRenderableContent`) uses the same set to decide whether a local
 * hit is authoritative, so a preserved-but-contentless hydration cannot pass
 * for content.
 */
export const SERVER_MANAGED_PROPS: ReadonlySet<string> = new Set<string>([
  ...DERIVED_BY_SERVER,
  'https://atomicdata.dev/properties/drive',
  // The inline genesis certificate: it verifies the resource's DID. `drive`
  // and `parent` matter especially for a GUEST who loaded a shared resource:
  // losing the parent's `drive` leaves a reply unstamped, so the drive-scoped
  // commit fan-out never delivers it to the owner. See
  // planning/commit-fanout-drive-isolation.md.
  GENESIS,
  core.properties.parent,
]);
