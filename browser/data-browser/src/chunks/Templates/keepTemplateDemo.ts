// @wc-ignore-file
import { core, server, type Store } from '@tomic/react';
import {
  readTemplateDemo,
  TEMPLATE_DEMO_KEY,
  type TemplateDemo,
} from './demoSession';

/** Promote the actual local graph so edits, documents and references stay intact. */
export async function keepTemplateDemo(
  store: Store,
  demo: TemplateDemo,
  name: string,
) {
  if (
    readTemplateDemo()?.drive !== demo.drive ||
    !store.isLocalOnlySubject(demo.drive)
  ) {
    throw new Error('This template preview is no longer available.');
  }

  const drive = await store.getResource(demo.drive);

  if (drive.error || !drive.hasClasses(server.classes.drive)) {
    throw new Error('This template preview could not be loaded.');
  }

  const home = await store.ensurePrivateDrive();
  await drive.set(core.properties.name, name);
  await drive.save();

  if (!home.getSubjects(server.properties.drives).includes(drive.subject)) {
    home.push(server.properties.drives, [drive.subject]);
  }

  await home.save();

  // Release the marker only after saving the drive and its switcher entry.
  // Keep local-only routing: adopting a preview must not enable hosting.
  localStorage.removeItem(TEMPLATE_DEMO_KEY);

  return drive;
}
