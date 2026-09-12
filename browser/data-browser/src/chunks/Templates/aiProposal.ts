// @wc-ignore-file
import { z } from 'zod';
import type { TemplateDefinition } from './model';
const schema = z.object({
  message: z.string().max(2000),
  title: z.string().min(1).max(80),
  tables: z.array(z.string()).max(6),
  documents: z
    .array(
      z.object({ name: z.string().min(1).max(80), text: z.string().max(4000) }),
    )
    .max(6),
});

export function parseTemplateProposal(
  text: string,
  catalog: readonly TemplateDefinition[],
): TemplateDefinition {
  const parsed = schema.parse(
    JSON.parse(text.replace(/^```(?:json)?\s*|\s*```$/g, '').trim()),
  );
  for (const id of parsed.tables)
    if (!catalog.some(t => t.id === id && t.entryPoints.includes('table')))
      throw new Error(
        'The AI proposed an unavailable template. Please try again.',
      );

  return {
    id: 'ai-proposal',
    version: '1',
    title: parsed.title,
    description: parsed.message,
    icon: '✨',
    entryPoints: ['workspace'],
    parts: [
      ...[...new Set(parsed.tables)].map((id, i) => ({
        kind: 'template' as const,
        key: `table-${i}`,
        template: id,
        version: '1',
      })),
      ...parsed.documents.map((d, i) => ({
        kind: 'document' as const,
        key: `document-${i}`,
        name: d.name,
        text: d.text,
      })),
    ],
  };
}
