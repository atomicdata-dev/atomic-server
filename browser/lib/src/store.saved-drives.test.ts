import { describe, expect, it, vi } from 'vitest';
import { server } from './ontologies/server.js';
import { testStore } from './test-store.js';

/**
 * What happens to a drive that cannot be recorded.
 *
 * `Agent.privateDriveSubject` refuses to derive a personal drive from a
 * signature that is not reproducible — rightly, because signing anyway once
 * minted 411 "My drive"s in a single session. The refusal even names the one
 * action that fixes it.
 *
 * That refusal used to be caught and sent to `console.warn`. The drive was
 * created and then belonged to no list, which from the outside is
 * indistinguishable from the drive having failed to exist.
 */
describe('recording a new drive on the personal drive', () => {
  it('lists the drive when the personal drive is available', async () => {
    const { store } = await testStore();

    const drive = await store.createDrive('Work', { personal: false });
    const personal = await store.ensurePrivateDrive();

    expect(personal.getSubjects(server.properties.drives)).toContain(
      drive.subject,
    );
  });

  it('refuses, rather than making a drive nobody can find', async () => {
    const { store } = await testStore();
    const before = store.getAllSubjects().length;

    vi.spyOn(store, 'ensurePrivateDrive').mockRejectedValue(
      new Error(
        "Cannot work out this account's private drive: its key signs " +
          'non-deterministically and no derived subject was stored. ' +
          'Sign in with the secret again to recompute it.',
      ),
    );

    // Thrown, not reported alongside a success. The caller shows "Failed to
    // create drive" and the reason; reporting it while also saying "Drive
    // created" is how someone ends up with a drive they were told about and
    // cannot find.
    await expect(
      store.createDrive('Work', { personal: false }),
    ).rejects.toThrow('Sign in with the secret again');

    // And nothing was written on the way out.
    expect(store.getAllSubjects().length).toBe(before);
  });
});

it('a local-only additional drive never posts its data to the selected server', async () => {
  const { store, posted } = await testStore();
  await store.ensurePrivateDrive();
  posted.length = 0;
  const drive = await store.createDrive('Browser collaboration', {
    personal: false,
    localOnly: true,
  });
  expect(store.isLocalOnlyDrive(drive.subject)).toBe(true);
  const ontology = drive.get(server.properties.defaultOntology);
  expect(
    posted.some(
      commit => commit.subject === drive.subject || commit.subject === ontology,
    ),
  ).toBe(false);
});
