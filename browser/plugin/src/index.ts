export * from './rpc.js';
export * from './types.js';
// Re-export @tomic/lib ontologies for convenience
// We use the full paths to help bundlers with tree-shaking.
export { core } from '@tomic/lib/ontologies/core.js';
export { server } from '@tomic/lib/ontologies/server.js';
export { dataBrowser } from '@tomic/lib/ontologies/dataBrowser.js';
export { ai } from '@tomic/lib/ontologies/ai.js';
export { collections } from '@tomic/lib/ontologies/collections.js';
export { commits } from '@tomic/lib/ontologies/commits.js';
// The run contract lives in @tomic/lib (the host needs it too); re-exported
// here so plugin authors import everything from one package.
export {
  hasBlockingProblems,
  LOCAL_REF_PREFIX,
  parseVerdict,
} from '@tomic/lib';
export type {
  CreateIntent,
  DestroyIntent,
  Intent,
  Problem,
  ProblemSeverity,
  RemoveIntent,
  SetIntent,
  Verdict,
} from '@tomic/lib';
