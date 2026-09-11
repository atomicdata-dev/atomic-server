// @wc-ignore-file
import { TEMPLATE_DEMO_KEY, readTemplateDemo } from './demoSession';
import {
  core,
  dataBrowser,
  enableLoro,
  server,
  type Store,
  type Resource,
} from '@tomic/react';
import { TABLE_TEMPLATES } from '../TablePage/tableTemplates';
import { instantiateTableTemplate } from './instantiateTable';

import type { TemplatePlan } from './model';

export interface TemplateInstance {
  release: TemplatePlan['release'];
  root: string;
  subjects: Record<string, string>;
}
/** Uses the same table and document writers as ordinary authoring. No HTTP import. */
export async function instantiateTemplate(
  store: Store,
  plan: TemplatePlan,
  target: { parent: string; drive: string },
): Promise<TemplateInstance> {
  // Reject unsupported plans before any writes, including missing catalog entries.
  for (const part of plan.parts) {
    if (part.kind === 'interactive-demo')
      throw new Error(
        'The interactive demo must be opened using its demo adapter.',
      );

    if (
      part.kind === 'table' &&
      !TABLE_TEMPLATES.some(t => t.id === part.catalogId && t.spec)
    ) {
      throw new Error(`Unknown table template: ${part.catalogId}`);
    }
  }

  const { addToOntology } = await import('../Demo/demoWorkspace');
  await enableLoro();
  const subjects: Record<string, string> = {};

  for (const part of plan.parts) {
    if (part.kind === 'table') {
      const result = await instantiateTableTemplate(
        store,
        part.catalogId,
        part.name,
        undefined,
        {
          parent: target.parent,
          driveSubject: target.drive,
          addToOntology: resource =>
            addToOntology(store, target.drive, resource),
        },
        plan.examples,
      );
      subjects[part.key] = result.tableSubject;
    } else if (part.kind === 'document') {
      const resource = await store.newResource({
        parent: target.parent,
        isA: dataBrowser.classes.documentV2,
        propVals: { [core.properties.name]: part.name },
      });
      const text = plan.examples ? (part.exampleText ?? part.text) : part.text;

      if (text) {
        const { applyPatchedJsonToLoroDocCollaborative } =
          await import('../RTE/applyPatchedJsonToLoroDocCollaborative');
        const loroDoc = resource.getLoroDoc();
        if (!loroDoc) throw new Error('Document storage is not ready.');
        await applyPatchedJsonToLoroDocCollaborative({
          store,
          subject: resource.subject,
          loroDoc,
          patchedJson: {
            type: 'doc',
            content: text.split('\n').map(line => ({
              type: 'paragraph',
              content: line ? [{ type: 'text', text: line }] : [],
            })),
          },
        });
      }

      await resource.save();
      subjects[part.key] = resource.subject;
    }
  }

  return { release: plan.release, root: target.parent, subjects };
}
export async function startTemplateDemo(
  store: Store,
  plan: TemplatePlan,
): Promise<string> {
  const db = store.getClientDb();
  if (!db) throw new Error('Enable local storage to preview this template.');
  await db.waitForReady();
  const { cleanupDemoDrive, stopDemoDirector } =
    await import('../Demo/startDemo');
  stopDemoDirector();
  const previous = readTemplateDemo();
  const previousDrive = previous?.previousDrive ?? store.getDrive() ?? '';
  if (previous) await cleanupDemoDrive(store, previous.drive);
  const agent = store.getAgent();
  if (!agent) throw new Error('Sign in before previewing a template.');
  await enableLoro();
  const drive: Resource = await store.newResource({
    isA: server.classes.drive,
    noParent: true,
    propVals: {
      [core.properties.name]: `${plan.title} demo`,
      [core.properties.read]: [agent.subject],
      [core.properties.write]: [agent.subject],
    },
  });
  // Register and track before the first save; a failed preview can still be cleaned up.
  store.registerLocalOnlyDrive(drive.subject);
  localStorage.setItem(
    TEMPLATE_DEMO_KEY,
    JSON.stringify({
      drive: drive.subject,
      template: plan.release.id,
      previousDrive,
    }),
  );
  await drive.save();
  await store.createDefaultOntology(drive);
  const instance = await instantiateTemplate(
    store,
    { ...plan, examples: true },
    { parent: drive.subject, drive: drive.subject },
  );
  store.setDrive(drive.subject);

  return Object.values(instance.subjects)[0] ?? drive.subject;
}
