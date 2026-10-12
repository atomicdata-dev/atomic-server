// @wc-ignore-file
import type { Store } from '@tomic/react';
import type { AIMessageContext } from './types';
import { shortenRefsDeep } from '@tomic/react';
import {
  buildClassContext,
  describeClassCompact,
  toCompact,
} from '@tomic/react';
import { getClassContextForAgent } from './resourceContextProviders';

/**
 * Processes atomic resources from context. Each attached resource is rendered
 * in compact JSON-AD with its `_schema` lines (mirroring get_atomic_resource
 * results), and tables additionally expand into their row-class schema, row
 * count, and a compact row sample — so the model can act on "this table"
 * without discovery tool calls.
 */

export const processAtomicResources = async (
  context: AIMessageContext[],
  store: Store,
) => {
  const atomicContext = context.filter(x => x.type === 'atomic-resource');

  if (atomicContext.length === 0) {
    return { resourcesContent: '' };
  }

  const blocks: string[] = [];

  for (const { subject } of atomicContext) {
    try {
      const resource = await store.getResource(subject);

      if (resource.error) {
        blocks.push(
          `Could not read attached resource ${subject}: ${resource.error.message}`,
        );
        continue;
      }

      const classes = resource.getClasses();
      const ctx = await buildClassContext(store, classes);
      const compact: Record<string, unknown> = await toCompact(
        store,
        resource,
        {
          includeCommitData: true,
          context: ctx,
        },
      );

      compact._schema = classes.map(c => describeClassCompact(ctx, c));

      const classContext = await getClassContextForAgent(
        store,
        resource,
        compact,
      );

      const lines = [
        `An atomicdata resource called ${resource.title}. Data:`,
        '```json',
        JSON.stringify(shortenRefsDeep(compact)),
        '```',
        ...(classContext ? [classContext] : []),
      ];

      blocks.push(lines.join('\n'));
    } catch (error) {
      blocks.push(
        `Could not read attached resource ${subject}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  return { resourcesContent: blocks.join('\n\n') };
};
