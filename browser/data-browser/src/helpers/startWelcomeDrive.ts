import { type Store } from '@tomic/react';
import { TEMPLATE_CATALOG } from '../chunks/Templates/catalog';
import { planTemplate } from '../chunks/Templates/model';

/**
 * Build the "Welcome to Atomic" drive for the agent that just started, as a
 * real drive made like one from the gallery. `localOnly` follows the personal
 * drive, so an identity that stays on this device keeps its welcome drive
 * there too and a later sign-in can still bring it along.
 *
 * Not tracked as a demo drive: nothing may wipe it.
 *
 * Returns the drive and the Welcome document to open.
 */
export async function startWelcomeDrive(
  store: Store,
  personalDrive: string,
): Promise<{ drive: string; landing: string }> {
  const { instantiateTemplate } =
    await import('../chunks/Templates/instantiate');
  const template = TEMPLATE_CATALOG.find(t => t.id === 'welcome')!;
  const plan = planTemplate(template, TEMPLATE_CATALOG, true);
  const drive = await store.createDrive(plan.title, {
    personal: false,
    localOnly: store.isLocalOnlyDrive(personalDrive),
  });
  const { subjects } = await instantiateTemplate(store, plan, {
    parent: drive.subject,
    drive: drive.subject,
  });

  await store.notifyResourceManuallyCreated(drive);

  return { drive: drive.subject, landing: subjects.welcome };
}
