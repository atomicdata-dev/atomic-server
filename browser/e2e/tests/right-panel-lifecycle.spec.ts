import { test, expect } from './fixtures';
import { before } from './test-utils';

for (const panel of ['followSession', 'comments', 'ai']) {
  test(`does not restore stale ${panel} panel from another session`, async ({
    page,
  }) => {
    await before({ page });
    await page.evaluate(
      value =>
        localStorage.setItem('atomic.rightPanel.active', JSON.stringify(value)),
      panel,
    );
    await page.reload();
    await expect(
      page.getByRole('button', { name: 'More', exact: true }),
    ).toBeVisible();
    await expect(
      page.locator(
        '[data-testid="follow-session-panel"][data-open], [data-testid="comments-panel"][data-open], [data-testid="ai-sidebar"][data-open]',
      ),
    ).toHaveCount(0);
  });
}

test('comments close when navigating to a page without a resource', async ({
  page,
}) => {
  await before({ page });
  await page.getByTestId('navbar-comments-button').click();
  await expect(page.getByTestId('comments-panel')).toHaveAttribute(
    'data-open',
    '',
  );
  await page.getByRole('link', { name: /Sync$/ }).click();
  await expect(page.getByTestId('comments-panel')).not.toHaveAttribute(
    'data-open',
    '',
  );
  await page.goBack();
  await expect(page.getByTestId('navbar-comments-button')).toBeVisible();
  await expect(page.getByTestId('comments-panel')).not.toHaveAttribute(
    'data-open',
    '',
  );
});

test('deleting an explicitly opened meeting closes its panel', async ({
  page,
}) => {
  await before({ page });
  await page.getByRole('button', { name: 'New Meeting' }).first().click();
  await page.getByRole('button', { name: 'Open chat', exact: true }).click();
  await expect(page.getByTestId('follow-session-panel')).toHaveAttribute(
    'data-open',
    '',
  );
  await page.evaluate(async () => {
    const subject = new URL(location.href).searchParams.get('subject')!;
    await window.store.getResourceLoading(subject).destroy();
  });
  await expect(page.getByTestId('follow-session-panel')).not.toHaveAttribute(
    'data-open',
    '',
  );
});

test('switching drives closes a panel without resurrecting it on return', async ({
  page,
}) => {
  await before({ page });
  const original = await page.evaluate(() => window.store.getDrive());
  await page.getByTestId('navbar-comments-button').click();
  await expect(page.getByTestId('comments-panel')).toHaveAttribute(
    'data-open',
    '',
  );
  await page.evaluate(async () => {
    const drive = await window.store.createDrive('Second panel test drive', {
      personal: false,
    });
    window.store.setDrive(drive.subject);
  });
  await expect(page.getByTestId('comments-panel')).not.toHaveAttribute(
    'data-open',
    '',
  );
  await page.evaluate(drive => window.store.setDrive(drive), original);
  await expect(page.getByTestId('comments-panel')).not.toHaveAttribute(
    'data-open',
    '',
  );
});
