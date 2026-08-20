export * from './rpc.js';
export * from './types.js';
export * from './run.js';
// Re-export @tomic/lib ontologies for convenience
// We use the full paths to help bundlers with tree-shaking.
export { core } from '@tomic/lib/ontologies/core.js';
export { server } from '@tomic/lib/ontologies/server.js';
export { dataBrowser } from '@tomic/lib/ontologies/dataBrowser.js';
export { ai } from '@tomic/lib/ontologies/ai.js';
export { collections } from '@tomic/lib/ontologies/collections.js';
export { commits } from '@tomic/lib/ontologies/commits.js';
