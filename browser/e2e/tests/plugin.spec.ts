import test, { expect } from './fixtures';
import {
  before,
  currentDriveTitle,
  fillSearchBox,
  inDialog,
  newDrive,
  newResource,
  setTitle,
  sidebarDriveButtonId,
  signIn,
  testFilePath,
} from './test-utils';

const BIRD =
  'https://atomicdata.dev/01k10mtpp8fkkmsd6tkm9qrqyw/defaultontology/class/bird';

test.describe('Plugins', () => {
  test.beforeEach(before);

  test('install a plugin', async ({ page }) => {
    // Two upload + commit + plugin-install chains, a full bird-creation
    // form, an iframe-driven picker, plus a reload-and-verify. The test
    // routinely needs 40-50s on a dev machine even when nothing is wrong.
    // test.slow() triples the default 60s budget.
    test.slow();
    await signIn(page);
    await newDrive(page);

    // Plugin must be installed BEFORE the folder is created. The plugin uses
    // `after_commit` + `host.commit` to set the canonical folder name, so it
    // only fires for commits that land *after* install. Render-time
    // (`on_resource_get`) transforms can't satisfy this assertion: WS sends
    // the persisted Loro snapshot (web_sockets.rs:172 KNOWN GAP), so the
    // browser never sees extender-modified propvals.
    await page.getByTestId(sidebarDriveButtonId).click();

    // Drive page now renders Tags / Default Ontology / Plugins as collapsible
    // sections. Expand the Plugins section so the Upload button is in the DOM.
    await page.getByRole('main').getByText('Plugins', { exact: true }).click();

    // Upload a plugin
    const fileChooserPromise = page.waitForEvent('filechooser');
    await page.getByRole('main').getByText('Upload Plugin').click();
    const fileChooser = await fileChooserPromise;

    await fileChooser.setFiles(testFilePath('test-plugin.zip'));

    await inDialog(page, async (dialog, closeWith) => {
      await expect(
        dialog.getByRole('heading', { name: 'Add Plugin' }),
      ).toBeVisible();
      await expect(
        dialog.getByText('ontola/test-plugin', { exact: true }),
      ).toBeVisible();
      await expect(dialog.getByText('v1.0.0', { exact: true })).toBeVisible();
      await expect(dialog.getByText('Storage', { exact: true })).toBeVisible();

      // Check if the install button correctly disables when the config is invalid
      const installButton = dialog.getByRole('button', { name: 'Install' });
      await expect(installButton).toBeEnabled();

      await dialog.getByLabel('Config').fill('{"folderPrefix": 5}');

      await expect(installButton).toBeDisabled();

      await dialog.getByLabel('Config').fill('{"folderPrefix": "My"}');

      await expect(installButton).toBeEnabled();

      // Install the plugin
      await closeWith('Install');
    });

    await expect(
      page.getByRole('link', { name: 'ontola/test-plugin' }),
    ).toBeVisible();

    // Now create the folder. The plugin's `after_commit` fires on the
    // folder's first commit and emits a follow-up commit setting the
    // canonical name to "{prefix} Problem".
    await newResource('folder', page);
    await setTitle(page, 'Problem');

    await page.reload();

    // The plugin's after_commit fires async, signs a host.commit, and the
    // rename then propagates over WS. That's a WASM invocation + a second
    // signed commit + a WS round trip on top of the reload above — under
    // dagger's CPU-constrained container 15s wasn't enough margin (observed
    // failures at this exact assertion in CI). test.slow() above triples the
    // *test's* budget but doesn't touch this call's own explicit timeout, so
    // widen it directly.
    await expect(
      page.getByTestId('editable-title').getByText('My Problem'),
    ).toBeVisible({ timeout: 30000 });

    // Removed: assertion that changing the plugin config (without a fresh
    // folder commit) re-renames existing folders. With the after_commit +
    // host.commit model the plugin only reacts to incoming commits, not to
    // its own config changes — config-driven re-render needs either
    // render-time view transforms (incompatible with the WS snapshot path)
    // or a host-driven reconcile pass on config change.

    // Test the custom view
    await newResource(BIRD, page);

    await page.getByLabel('name').fill('Duck');

    await page.getByTestId('input-characteristics-add-resource').click();

    {
      const pickOption = await fillSearchBox(
        page,
        'Search for a resource or enter a URL',
        '',
      );
      await pickOption('water');
    }

    await page.getByRole('button', { name: 'Save' }).click();

    {
      const frame = page.frameLocator('#custom-view');

      expect(frame).not.toBeNull();
      if (!frame) throw new Error('Frame not found');

      // Iframe needs to load ui.js, open its own WS, fetch the resource —
      // give it more headroom than the default 5s actionTimeout.
      await expect(frame.getByRole('heading', { name: 'Duck' })).toBeVisible({
        timeout: 20000,
      });
      await expect(
        frame.getByText('This is a custom view for the Bird class.'),
      ).toBeVisible();
      await expect(frame.getByText('Water')).toBeVisible();

      await frame
        .getByRole('button', { name: 'Select favorite folder' })
        .click();

      await inDialog(page, async (dialog, closeWith) => {
        await expect(
          dialog.getByRole('heading', { name: 'Select a folder' }),
        ).toBeVisible();
        await expect(
          dialog.getByText("Pick the bird's favorite folder"),
        ).toBeVisible();
        // Type a query so the picker filters to the renamed folder.
        // KV search is immediate; wait only for the SearchBox debounce.
        const pickOption = await fillSearchBox(
          dialog,
          'Search for a folder',
          'My',
        );
        await expect(
          dialog.getByTestId('searchbox-results').getByText('My Problem'),
        ).toBeVisible({ timeout: 5000 });
        await pickOption('My Problem');
        await closeWith('Confirm');
      });

      await expect(frame.getByText('My Problem')).toBeVisible();
    }

    // Check if the view can commit by refreshing and checking the favorite folder.
    await page.reload();

    {
      const frame = page.frameLocator('#custom-view');

      expect(frame).not.toBeNull();
      if (!frame) throw new Error('Frame not found');

      await expect(frame.getByText('My Problem')).toBeVisible({
        timeout: 15000,
      });
    }

    // Navigate back to the plugin
    await currentDriveTitle(page).click();
    // Plugins section state can collapse after reloads; expand it again.
    await page.getByRole('main').getByText('Plugins', { exact: true }).click();
    await page.getByRole('link', { name: 'ontola/test-plugin' }).click();

    // Uninstall the plugin
    await page.getByRole('button', { name: 'Uninstall' }).click();

    await inDialog(page, async (dialog, closeWith) => {
      await expect(
        dialog.getByRole('heading', { name: 'Uninstall Plugin' }),
      ).toBeVisible();
      await closeWith('Uninstall');
    });

    await expect(page.getByText('Plugin uninstalled')).toBeVisible();

    // After uninstall the plugin resource is destroyed, so reloading on its
    // URL would 404. Navigate to the drive page first.
    await page.getByTestId(sidebarDriveButtonId).click();

    // Drive page nests children under a 'Resources' collapsible section
    // (commit 32db1349). It usually starts collapsed on the drive view — but
    // a bare click is a TOGGLE, and under load the section can have expanded
    // itself (children landing after the first paint) so a blind click
    // CLOSES it and the assertion below starves with everything looking
    // idle. Same lesson as the menu helpers: drive the toggle by the
    // outcome, retrying the click only while the folder is not visible.
    //
    // The folder keeps its prefixed name after uninstall: with the
    // after_commit + host.commit model the rename was a real commit, so it
    // persists.
    const renamedFolder = page
      .getByRole('main')
      .getByRole('button', { name: 'My Problem' });
    await expect(async () => {
      if (!(await renamedFolder.isVisible().catch(() => false))) {
        await page
          .getByRole('main')
          .getByText('Resources', { exact: true })
          .click();
      }

      await expect(renamedFolder).toBeVisible({ timeout: 3000 });
    }).toPass({ timeout: 30000 });

    // Same toggle discipline for the Plugins section.
    const noPlugins = page.getByText('No plugins installed');
    await expect(async () => {
      if (!(await noPlugins.isVisible().catch(() => false))) {
        await page
          .getByRole('main')
          .getByText('Plugins', { exact: true })
          .click();
      }

      await expect(noPlugins).toBeVisible({ timeout: 3000 });
    }).toPass({ timeout: 20000 });

    // Check if the custom view is gone.
    await page
      .getByTestId('sidebar')
      .getByRole('button', { name: 'Duck' })
      .click();
    await expect(page.locator('#custom-view')).toHaveCount(0);
    await expect(page.getByTestId('editable-title')).toHaveText('Duck');
  });
});
