import { test, expect } from './fixtures';
import { before } from './test-utils';
import { enableAIForTesting, setupAIRouteMocks } from './ai-mock';
import { ai, core, dataBrowser } from '@tomic/lib';

test('AI chat discovery includes both duplicate folders and root chats, scoped to the private drive', async ({
  page,
}) => {
  await enableAIForTesting(page);
  await setupAIRouteMocks(page);
  await before({ page });
  const titles = await page.evaluate(
    async ({ aiClass, folderClass, name, pointer }) => {
      const store = window.store;
      const drive = await store.getResource(await store.privateDriveSubject());

      const make = async (parent: string, isA: string, title: string) => {
        const res = await store.newResource({
          parent,
          isA,
          propVals: { [name]: title },
        });
        await res.save();
        store.notifyResourceManuallyCreated(res);

        return res;
      };

      const first = await make(drive.subject, folderClass, 'AI Chats');
      const second = await make(drive.subject, folderClass, 'AI Chats');
      await drive.set(pointer, second.subject);
      await drive.save();
      await make(first.subject, aiClass, 'Phone conversation');
      await make(second.subject, aiClass, 'Desktop conversation');
      await make(drive.subject, aiClass, 'Legacy root conversation');
      await make(second.subject, folderClass, 'Not a conversation');
      const otherDrive = await store.createDrive('Other workspace', {
        personal: false,
        localOnly: true,
      });
      await make(otherDrive.subject, aiClass, 'Other drive conversation');

      return [
        'Phone conversation',
        'Desktop conversation',
        'Legacy root conversation',
      ];
    },
    {
      aiClass: ai.classes.aiChat,
      folderClass: dataBrowser.classes.folder,
      name: core.properties.name,
      pointer: ai.properties.aiChatsFolder,
    },
  );
  const panel = page.getByTestId('ai-chats-panel');

  for (const title of titles) {
    await expect(
      panel.getByRole('link', { name: title, exact: true }),
    ).toBeVisible();
  }

  await expect(
    panel.getByRole('link', { name: 'Other drive conversation' }),
  ).toHaveCount(0);
  await expect(
    panel.getByRole('link', { name: 'Not a conversation' }),
  ).toHaveCount(0);
  await page.reload();

  for (const title of titles) {
    await expect(
      panel.getByRole('link', { name: title, exact: true }),
    ).toBeVisible();
  }
});
