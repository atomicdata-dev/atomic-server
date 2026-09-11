import { test, expect } from '@playwright/test';
import { devDrive, FRONTEND_URL } from './test-utils';
for (const keepEdits of [false, true]) {
test(`template adoption ${keepEdits ? 'keeps edited content' : 'starts fresh without samples'}`, async ({ page }) => {
  test.setTimeout(120000);
  await devDrive(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${FRONTEND_URL}/app/new-drive`);
  await expect(page.getByRole('button', {name:'Close', exact:true})).toBeVisible();
  await expect(page.getByRole('link', { name: 'create a blank drive', exact: true })).toBeVisible();
  // The lazy AI composer must not pull focus/scroll away from the gallery.
  await expect(page.locator('[contenteditable=true]')).toBeAttached();
  await expect(page.locator('[contenteditable=true]')).not.toBeFocused();
  await expect(page.getByRole('link', {name: 'create a blank drive', exact:true})).toBeInViewport();
  await expect(page.getByTestId('sidebar')).toHaveCount(0);
  await expect(page.getByRole('button', {name: /Show \/ hide sidebar/})).toHaveCount(0);
  await page.getByRole('button', { name: 'Preview template', exact: true }).first().click();
  await expect(page.getByRole('button', { name: 'Use this template', exact: true })).toBeVisible({ timeout: 60000 });
  await expect(page.getByTestId('sidebar')).toBeInViewport();
  await page.getByRole('button', {name: /Show \/ hide sidebar/}).click();
  const tabs = page.getByRole('tablist');
  await expect(tabs).toHaveCSS('overflow-x', 'auto');
  const tabScroll = await tabs.evaluate(el => {
    el.scrollLeft = el.scrollWidth;
    return el.scrollLeft;
  });
  expect(tabScroll).toBeGreaterThan(0);
  const previewBar = await page.getByRole('region', {name: 'Template preview'}).boundingBox();
  const navigation = await page.getByLabel('navigation', {exact: true}).boundingBox();
  expect(previewBar!.y + previewBar!.height).toBeLessThanOrEqual(navigation!.y);
  for (const name of ['Use this template', 'Back']) {
    const box = await page.getByRole('button', {name, exact: true}).boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  }
  const demo = await page.evaluate(() => JSON.parse(localStorage.getItem('atomic.templateDemo')!));
  expect(await page.evaluate(drive => window.store.isLocalOnlySubject(drive), demo.drive)).toBe(true);
  // Edit a real preview resource before choosing what to keep.
  await page.evaluate(async drive => {
    const store = window.store;
    const children = await store.queryLocalDb({ property: 'https://atomicdata.dev/properties/parent', value: drive });
    for (const subject of children?.subjects ?? []) {
      const resource = await store.getResource(subject);
      if (resource.get('https://atomicdata.dev/properties/name') === 'Lecture notes') {
        await resource.set('https://atomicdata.dev/properties/name', 'My temporary demo edit');
        await resource.save();
      }
    }
  }, demo.drive);
  await page.getByRole('button', { name: 'Use this template', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Give your space a name' })).toBeVisible();
  await expect(page.getByLabel('Drive name')).toHaveValue('Student');
  expect(await page.getByLabel('Drive name').evaluate((input: HTMLInputElement) =>
    [input.selectionStart, input.selectionEnd],
  )).toEqual([0, 'Student'.length]);
  if (keepEdits) await page.getByLabel('Keep demo content and my edits').check();
  await page.getByLabel('Drive name').fill('My study workspace');
  await page.getByRole('button', { name: 'Create drive', exact: true }).click();
  await expect(page).not.toHaveURL(/new-drive/, { timeout: 60000 });
  const result = await page.evaluate(async () => {
    const store = window.store;
    const drive = store.getDrive()!;
    const children = await store.queryLocalDb({ property: 'https://atomicdata.dev/properties/parent', value: drive });
    const names = [];
    let sampleRows = 0;
    for (const subject of children?.subjects ?? []) {
      names.push((await store.getResource(subject)).get('https://atomicdata.dev/properties/name'));
      const nested = await store.queryLocalDb({ property: 'https://atomicdata.dev/properties/parent', value: subject });
      for (const child of nested?.subjects ?? []) {
        const name = (await store.getResource(child)).get('https://atomicdata.dev/properties/name');
        if (typeof name === 'string' && name.startsWith('Example ')) sampleRows++;
      }
    }
    return { drive, names, sampleRows, demo: localStorage.getItem('atomic.templateDemo') };
  });
  if (keepEdits) expect(result.drive).toBe(demo.drive);
  else expect(result.drive).not.toBe(demo.drive);
  expect(result.names).toContain('Assignments');
  expect(result.names).toContain(keepEdits ? 'My temporary demo edit' : 'Lecture notes');
  expect(result.demo).toBeNull();
  if (keepEdits) expect(result.sampleRows).toBeGreaterThan(0);
  else {
    expect(result.names).not.toContain('My temporary demo edit');
    expect(result.sampleRows).toBe(0);
  }
});
}
test('blank drive remains a short path without feedback covering it on mobile', async ({ page }) => {
  await page.setViewportSize({width:390,height:844});
  await devDrive(page);
  await page.goto(`${FRONTEND_URL}/app/new-drive`);
  await expect(page.getByRole('button', {name:'Close', exact:true})).toBeVisible();
  const blank = page.getByRole('button', { name: 'Create a blank drive' });
  await blank.scrollIntoViewIfNeeded();
  const blankBox = await blank.boundingBox();
  const feedbackBox = await page.getByRole('button', {name: 'Feedback', exact:true}).boundingBox();
  expect(feedbackBox!.y).toBeGreaterThanOrEqual(blankBox!.y + blankBox!.height);
  await blank.click();
  await page.getByLabel('Drive name').fill('Blank example');
  await page.getByRole('button', { name: 'Create drive', exact: true }).click();
  await expect(page).not.toHaveURL(/new-drive/);
});

test('interactive demo returns to template selection from the top bar', async ({ page }) => {
  test.setTimeout(120000);
  await devDrive(page);
  await page.setViewportSize({width:390,height:844});
  await page.goto(`${FRONTEND_URL}/app/demo`);
  const exit = page.getByRole('button', {name:'Back', exact:true});
  await expect(exit).toBeVisible({timeout:90000});
  await expect(exit).toHaveCount(1);
  const bar = await page.getByRole('region', {name:'Template preview'}).boundingBox();
  const nav = await page.getByLabel('navigation', {exact:true}).boundingBox();
  expect(bar!.y + bar!.height).toBeLessThanOrEqual(nav!.y);
  await exit.click();
  await expect(exit).toHaveCount(0);
  await expect(page.getByRole('link', {name:'create a blank drive', exact:true})).toBeVisible();
});

test('AI setup can be dismissed and reopened without trapping the gallery', async ({ page }) => {
  await devDrive(page);
  await page.setViewportSize({width:1280,height:900});
  await page.goto(`${FRONTEND_URL}/app/new-drive`);
  for (const method of ['outside', 'escape', 'close']) {
    await page.getByRole('button', {name:'Set up AI', exact:true}).click();
    const title = page.getByRole('heading', {name:'Connect a model to use Atomic Assistant'});
    await expect(title).toBeVisible();
    if (method === 'outside') await page.mouse.click(5, 5);
    else if (method === 'escape') await page.keyboard.press('Escape');
    else await page.getByRole('button', {name:'close', exact:true}).click();
    await expect(title).not.toBeVisible();
  }
});
