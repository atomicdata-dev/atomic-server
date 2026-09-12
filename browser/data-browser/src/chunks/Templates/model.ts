// @wc-ignore-file
/** Portable template definitions. UI components and executable code stay in adapters. */
export interface TemplateDefinition {
  id: string;
  version: string;
  title: string;
  description: string;
  icon: string;
  entryPoints: Array<'table' | 'workspace'>;
  parts: TemplatePart[];
}
export type TemplatePart =
  | {
      key: string;
      kind: 'template';
      template: string;
      version: string;
      name?: string;
    }
  | { key: string; kind: 'table'; catalogId: string; name: string }
  | {
      key: string;
      kind: 'document';
      name: string;
      text: string;
      exampleText?: string;
    }
  | { key: string; kind: 'interactive-demo' };
export interface TemplatePlan {
  release: { id: string; version: string };
  title: string;
  examples: boolean;
  parts: Array<Exclude<TemplatePart, { kind: 'template' }>>;
}
export function planTemplate(
  template: TemplateDefinition,
  catalog: readonly TemplateDefinition[],
  examples = false,
): TemplatePlan {
  const parts: TemplatePlan['parts'] = [];
  const keys = new Set<string>();

  function visit(
    current: TemplateDefinition,
    prefix: string,
    ancestry: Set<string>,
  ) {
    const release = `${current.id}@${current.version}`;
    if (ancestry.has(release))
      throw new Error(`Circular template dependency: ${release}`);
    const next = new Set(ancestry).add(release);

    for (const part of current.parts) {
      const key = `${prefix}${part.key}`;
      if (keys.has(key)) throw new Error(`Duplicate template key: ${key}`);
      keys.add(key);

      if (part.kind === 'template') {
        const child = catalog.find(
          t => t.id === part.template && t.version === part.version,
        );
        if (!child)
          throw new Error(
            `Missing template dependency: ${part.template}@${part.version}`,
          );
        const start = parts.length;
        visit(child, `${key}/`, next);

        if (part.name && parts.length === start + 1 && 'name' in parts[start]) {
          parts[start] = {
            ...parts[start],
            name: part.name,
          } as TemplatePlan['parts'][number];
        }
      } else {
        parts.push({ ...part, key });
      }
    }
  }

  visit(template, '', new Set());

  return {
    release: { id: template.id, version: template.version },
    title: template.title,
    examples,
    parts,
  };
}
