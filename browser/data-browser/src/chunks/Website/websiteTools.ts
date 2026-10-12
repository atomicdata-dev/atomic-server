// @wc-ignore-file
import { tool } from 'ai';
import { z } from 'zod';
import type { Store } from '@tomic/lib';
import {
  createWebsite,
  readWebsite,
  updateWebsite,
  websiteConfigSchema,
} from './websiteModel';
import { buildWebsiteArtifact } from './websiteExport';
import { expandSubject, shortenRefsDeep } from '@tomic/react';

export function websiteTools(store: Store, drive: string) {
  const expandConfig = (raw: z.infer<typeof websiteConfigSchema>) => ({
    ...raw,
    pages: raw.pages.map(page => ({
      ...page,
      documents: page.documents.map(expandSubject),
      media: page.media?.map(image => ({
        ...image,
        subject: expandSubject(image.subject),
      })),
      tables: page.tables.map(table => ({
        ...table,
        table: expandSubject(table.table),
        rows: table.rows.map(expandSubject),
        columns: table.columns.map(column => ({
          ...column,
          property: expandSubject(column.property),
        })),
      })),
    })),
  });

  return {
    create_website: tool({
      description:
        'Create a website workspace from existing Atomic documents and explicitly selected table rows/fields. Use this for websites and publications, rather than create_app. Content stays editable in the original document editor and tables; do not copy it into CSS or invent data. Create/edit documents with the document tools first. Design with theme values and custom CSS (no external URLs or scripts). Pages have unique lowercase paths ending in /, including /. Compose each page with optional sections: ordered intro/document/table/gallery references by index (gallery uses index 0 and page.media), span full/half/third, and CSS className. Omitted sections keep the original layout. Use table.search=true for a searchable plugin view of exactly the selected snapshot rows and columns. For standalone photos use page.media with explicitly selected File subjects, alt text and optional captions; a gallery section renders those images. For product photos, use an atomicURL column with File classtype on the original table and include that column. Decide from context whether images illustrate a page or belong to records; ask only when unclear. Never put image bytes in CSS. No arbitrary plugin JavaScript or Forms yet. The tool validates a static export before saving. No public deployment occurs.',
      inputSchema: z.object({ config: websiteConfigSchema }),
      execute: async ({ config }) => {
        try {
          const parsed = expandConfig(config);
          const check = await buildWebsiteArtifact(store, 'draft', parsed);
          const resource = await createWebsite(store, drive, parsed);

          return shortenRefsDeep({
            website: resource.subject,
            checkedPages: Object.keys(check.files),
            status: 'private draft',
            next: 'Open the website for its preview. Use describe_website and update_website to iterate. Release/export controls are on that page; Publish site / Update site explicitly publishes through configured hosting.',
          });
        } catch (error) {
          return { error: String(error) };
        }
      },
    }),
    describe_website: tool({
      description:
        'Read the current website design and source references before editing it. Referenced documents and selected table fields remain the content source. This does not traverse other data.',
      inputSchema: z.object({ website: z.string() }),
      execute: async ({ website }) => {
        try {
          const resource = await store.getResource(expandSubject(website));
          const { config } = await readWebsite(store, drive, resource);

          return shortenRefsDeep({ website: resource.subject, config });
        } catch (error) {
          return { error: String(error) };
        }
      },
    }),
    update_website: tool({
      description:
        'Replace an existing website draft configuration after describe_website. Keep existing page/content references unless the user requested changes. Edit document text and table fields at their sources. Can change colors, typography, CSS layout, routes, selected content, page.sections ordering/column spans/custom classes, page.media gallery images and table.search. Build distinctive compositions with page-layout, span-full, span-half, span-third and section className selectors. Checks the full static export before saving. Does not replace any frozen release or publish publicly. CSS classes: brand, intro, eyebrow, cards, card; semantic header/nav/main/article/section/footer elements. Do not claim browser/visual verification from this tool: it checks export validity only.',
      inputSchema: z.object({
        website: z.string(),
        config: websiteConfigSchema,
      }),
      execute: async ({ website, config }) => {
        try {
          const resource = await store.getResource(expandSubject(website));
          const parsed = expandConfig(config);
          const check = await buildWebsiteArtifact(
            store,
            resource.subject,
            parsed,
          );
          await updateWebsite(store, drive, resource, parsed);

          return {
            updated: true,
            checkedPages: Object.keys(check.files),
            status: 'private draft; existing release unchanged',
          };
        } catch (error) {
          return { error: String(error) };
        }
      },
    }),
  };
}
