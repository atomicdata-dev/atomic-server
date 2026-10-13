// @wc-ignore-file
import { z } from 'zod';
import {
  core,
  Datatype,
  ensureSchema,
  server,
  type Resource,
  type Store,
  type EnsuredSchema,
  type SchemaSpec,
} from '@tomic/lib';

const resourceSubject = z.string().min(1).max(2048);
const route = z
  .string()
  .regex(
    /^\/(?:[a-z0-9]+(?:-[a-z0-9]+)*\/)*$/,
    'Use / or lowercase paths with a trailing slash, such as /about/.',
  );

export const websiteConfigSchema = z
  .object({
    version: z.literal(1),
    title: z.string().min(1).max(120),
    description: z.string().max(400),
    language: z.string().regex(/^[a-z]{2,3}(?:-[A-Z]{2})?$/),
    accent: z.string().regex(/^#[0-9a-fA-F]{6}$/),
    background: z.string().regex(/^#[0-9a-fA-F]{6}$/),
    font: z.enum(['sans', 'serif']),
    // Design only. Content is always resolved from explicitly selected resources.
    css: z
      .string()
      .max(20000)
      .refine(
        value => !/[<\\]|@import|url\s*\(/i.test(value),
        'CSS cannot contain markup, escaped tokens or external resources.',
      ),
    pages: z
      .array(
        z
          .object({
            path: route,
            title: z.string().min(1).max(120),
            documents: z.array(resourceSubject).max(30),
            media: z
              .array(
                z
                  .object({
                    subject: resourceSubject,
                    alt: z.string().max(400),
                    caption: z.string().max(400).optional(),
                  })
                  .strict(),
              )
              .max(30)
              .optional(),
            sections: z
              .array(
                z
                  .object({
                    kind: z.enum(['intro', 'document', 'table', 'gallery']),
                    index: z.number().int().min(0).max(29),
                    span: z.enum(['full', 'half', 'third']),
                    className: z.string().regex(/^[a-zA-Z0-9 _-]{0,120}$/),
                  })
                  .strict(),
              )
              .min(1)
              .max(60)
              .optional(),
            tables: z
              .array(
                z
                  .object({
                    table: resourceSubject,
                    title: z.string().max(120),
                    layout: z.enum(['grid', 'table']),
                    search: z.boolean().optional(),
                    // Explicit rows prevent newly added private records entering a release.
                    rows: z.array(resourceSubject).max(200),
                    columns: z
                      .array(
                        z.object({
                          property: resourceSubject,
                          label: z.string().max(120),
                        }),
                      )
                      .min(1)
                      .max(20),
                  })
                  .strict(),
              )
              .max(10),
          })
          .strict(),
      )
      .min(1)
      .max(30),
  })
  .strict()
  .superRefine((config, ctx) => {
    if (new Set(config.pages.map(p => p.path)).size !== config.pages.length)
      ctx.addIssue({ code: 'custom', message: 'Page paths must be unique.' });

    for (const page of config.pages) {
      const seen = new Set<string>();

      for (const section of page.sections ?? []) {
        const key = `${section.kind}:${section.index}`;
        if (
          seen.has(key) ||
          (section.kind === 'document' &&
            section.index >= page.documents.length) ||
          (section.kind === 'table' && section.index >= page.tables.length) ||
          (section.kind === 'intro' && section.index !== 0) ||
          (section.kind === 'gallery' &&
            (section.index !== 0 || !page.media?.length))
        )
          ctx.addIssue({
            code: 'custom',
            message: 'Sections must reference valid content once per page.',
          });
        seen.add(key);
      }
    }

    if (!config.pages.some(p => p.path === '/'))
      ctx.addIssue({
        code: 'custom',
        message: 'A website needs a home page at /.',
      });
  });
export type WebsiteConfig = z.infer<typeof websiteConfigSchema>;

export const WEBSITE_SPEC: SchemaSpec = {
  properties: [
    {
      shortname: 'website-design',
      name: 'Website design',
      description:
        'Draft routes, appearance and explicitly selected content. JSON text.',
      datatype: Datatype.STRING,
    },
    {
      shortname: 'website-release',
      name: 'Website release',
      description:
        'A private frozen static export. This does not make the website public.',
      datatype: Datatype.ATOMIC_URL,
    },
    {
      shortname: 'website-artifact',
      name: 'Website artifact',
      description: 'Versioned static release manifest as JSON text.',
      datatype: Datatype.STRING,
    },
  ],
  classes: [
    {
      shortname: 'website-project',
      name: 'Website',
      description:
        'A website authored in Atomic Assistant, using existing documents and tables.',
      requires: ['website-design'],
    },
    {
      shortname: 'website-export',
      name: 'Website export',
      description: 'A frozen website ready for static hosting.',
      requires: ['website-artifact'],
    },
  ],
};
export function starterWebsite(
  title = 'My website',
  document?: string,
): WebsiteConfig {
  return {
    version: 1,
    title,
    description: 'Made with Atomic',
    language: 'en',
    accent: '#315c49',
    background: '#f5f3eb',
    font: 'serif',
    css: '',
    pages: [
      {
        path: '/',
        title: 'Home',
        documents: document ? [document] : [],
        tables: [],
      },
    ],
  };
}
export async function createWebsite(
  store: Store,
  drive: string,
  config: WebsiteConfig,
) {
  const parsed = websiteConfigSchema.parse(config);
  await assertPrivateWebsiteParent(store, drive);
  const schema = await ensureSchema(store, drive, WEBSITE_SPEC);
  const resource = await store.newResource({
    parent: drive,
    isA: [schema.classes['website-project']],
    propVals: {
      [core.properties.name]: parsed.title,
      [schema.properties['website-design']]: JSON.stringify(parsed),
    },
  });
  await saveWebsiteResource(resource);

  return resource;
}
export async function readWebsite(
  store: Store,
  drive: string,
  resource: Resource,
) {
  const schema = await findWebsiteSchema(store, drive);
  if (
    !schema.classes?.['website-project'] ||
    !resource.hasClasses(schema.classes['website-project'])
  )
    throw new Error('This resource is not a website.');
  const property = schema.properties?.['website-design'];
  if (!property) throw new Error('Website schema is missing.');
  const config = websiteConfigSchema.parse(
    JSON.parse(String(resource.get(property))),
  );

  return { config, schema, property };
}
export async function updateWebsite(
  store: Store,
  drive: string,
  resource: Resource,
  config: WebsiteConfig,
) {
  const parsed = websiteConfigSchema.parse(config);
  await assertPrivateWebsiteParent(store, resource.subject);
  const { property } = await readWebsite(store, drive, resource);
  await resource.set(property, JSON.stringify(parsed));
  await resource.set(core.properties.name, parsed.title);
  await saveWebsiteResource(resource);
}

/** Confidential authoring cannot inherit public rights from a parent. */
export async function assertPrivateWebsiteParent(
  store: Store,
  subject: string,
) {
  const visited = new Set<string>();
  let next: string | undefined = subject;

  while (next) {
    if (visited.has(next) || visited.size >= 32)
      throw new Error('Cannot establish private website ancestry.');
    visited.add(next);
    const resource: Resource = await store.getResource(next);
    if (resource.error || resource.loading)
      throw new Error('Cannot verify website permissions yet.');

    for (const property of [core.properties.read, core.properties.write]) {
      const rights = resource.get(property);
      if (
        Array.isArray(rights) &&
        rights.includes('https://atomicdata.dev/agents/publicAgent')
      )
        throw new Error(
          'Create the website in a private drive. Public parents cannot protect drafts.',
        );
    }

    const parent: unknown = resource.get(core.properties.parent);
    next = typeof parent === 'string' ? parent : undefined;
  }
}

/** Resolve only this feature's native identities, not every unrelated ontology term. */
export async function findWebsiteSchema(
  store: Store,
  drive: string,
): Promise<Partial<EnsuredSchema>> {
  const root = await store.getResource(drive);
  const parent = root.get(server.properties.defaultOntology);
  if (typeof parent !== 'string') return {};
  const resolve = async (
    kind: 'class' | 'property',
    specs: { shortname: string }[],
  ) =>
    Object.fromEntries(
      (
        await Promise.all(
          specs.map(async spec => {
            const resource = await store.findByLocalId(
              drive,
              parent,
              `schema:${kind}:${spec.shortname}`,
            );

            return resource ? [spec.shortname, resource.subject] : undefined;
          }),
        )
      ).filter((entry): entry is string[] => entry !== undefined),
    );
  const [classes, properties] = await Promise.all([
    resolve('class', WEBSITE_SPEC.classes),
    resolve('property', WEBSITE_SPEC.properties),
  ]);

  return { classes, properties };
}

/** Local/outbox writes are not confirmation that a release is durable. */
export async function saveWebsiteResource(resource: Resource) {
  const receipt = await resource.saveWithReceipt();
  if (receipt.status !== 'noop' && !receipt.server)
    throw new Error(
      `Changes remain pending locally for ${resource.subject}. Reconnect and save this resource before creating another release.`,
    );
}
