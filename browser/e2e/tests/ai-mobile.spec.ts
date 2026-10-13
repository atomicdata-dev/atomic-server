import { test, expect } from '@playwright/test';
import { before } from './test-utils';
import {
  enableAIForTesting,
  openAISidebar,
  setupAIRouteMocks,
  setupScriptedToolCallMocks,
  sendChatMessage,
} from './ai-mock';

test('mobile AI chat fills the width and keeps its composer above the keyboard', async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setupAIRouteMocks(page);
  // A long saved title must leave room for both header action buttons.
  await page.route('https://openrouter.ai/api/v1/chat/completions**', route => {
    if (route.request().postDataJSON().stream) return route.fallback();

    return route.fulfill({
      json: {
        id: 'chat-title-test',
        object: 'chat.completion',
        created: 1234567890,
        model: '~google/gemini-flash-latest',
        choices: [
          {
            index: 0,
            message: {
              role: 'assistant',
              content: 'Planning a detailed project with AI chat',
            },
            finish_reason: 'stop',
          },
        ],
        usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
      },
    });
  });

  await enableAIForTesting(page);
  await before({ page });
  await openAISidebar(page);
  const panel = page.getByTestId('ai-sidebar');
  const composer = panel.getByTestId('assistant-file-dropzone');
  await expect(composer.locator('[contenteditable="true"]')).toBeVisible();
  await expect(
    panel.getByRole('heading', { name: 'AI chat', exact: true }),
  ).toBeVisible();
  await expect
    .poll(async () => Math.round((await panel.boundingBox())!.width))
    .toBe(390);
  await expect
    .poll(async () => Math.round((await panel.boundingBox())!.x))
    .toBe(0);
  await expect(
    panel.getByRole('combobox', { name: 'Model', exact: true }),
  ).toHaveCount(0);
  await panel
    .getByRole('button', { name: 'AI Chat options', exact: true })
    .click();
  await expect(
    page.getByRole('combobox', { name: 'Model', exact: true }),
  ).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(
    page.getByRole('combobox', { name: 'Model', exact: true }),
  ).toHaveCount(0);
  await sendChatMessage(page, 'Hello');
  await expect(
    panel.getByText('This is a mock AI response.', { exact: true }),
  ).toBeVisible();

  for (const testId of ['ai-message-text', 'ai-user-message']) {
    await expect
      .poll(async () =>
        panel.getByTestId(testId).evaluate(element => {
          const parentWidth =
            element.parentElement!.getBoundingClientRect().width;

          return Math.abs(parentWidth - element.getBoundingClientRect().width);
        }),
      )
      .toBeLessThanOrEqual(1);
  }

  await expect(panel.getByText('Tokens used:', { exact: false })).toHaveCount(
    0,
  );
  // The app's keyboard hook publishes this inset when Android covers the
  // layout viewport. Exercise that layout without requiring a real keyboard.
  await page.evaluate(() =>
    document.documentElement.style.setProperty('--keyboard-inset', '320px'),
  );
  await expect
    .poll(async () => {
      const box = (await composer.boundingBox())!;

      return box.y + box.height;
    })
    .toBeLessThanOrEqual(524);
  await expect
    .poll(async () => (await composer.boundingBox())!.height)
    .toBeLessThan(140);
  const resourceMenu = panel.getByRole('button', {
    name: 'Chat resource actions',
    exact: true,
  });
  await expect(resourceMenu).toBeInViewport();
  await expect
    .poll(async () => {
      const button = (await resourceMenu.boundingBox())!;

      return button.x + button.width;
    })
    .toBeLessThanOrEqual(390);
  await expect
    .poll(() =>
      panel.evaluate(element => element.scrollWidth - element.clientWidth),
    )
    .toBeLessThanOrEqual(1);
  await page.screenshot({ path: 'test-results/ai-chat-header-menu.png' });
  await panel
    .getByRole('button', { name: 'AI Chat options', exact: true })
    .click();
  await expect(
    page.getByRole('combobox', { name: 'Model', exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/Tokens used:.*input,.*output/)).toBeVisible();
  await page.keyboard.press('Escape');
  await panel
    .getByRole('button', { name: 'Chat resource actions', exact: true })
    .click();
  await expect(page.getByRole('menuitem', { name: /Data View/ })).toBeVisible();
  await page.screenshot({
    path: 'test-results/ai-chat-resource-menu-open.png',
    animations: 'disabled',
  });
  // Navigate through the chat menu, not the underlying drive's menu.
  await page.getByRole('menuitem', { name: /Normal View/ }).click();
  // Mobile navigation dismisses the full-screen chat to reveal its destination.
  await expect(panel).not.toHaveAttribute('data-open', '');
  await expect(
    page
      .getByRole('main')
      .getByText('This is a mock AI response.', { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .getByRole('main')
      .getByRole('button', { name: 'Chat resource actions', exact: true }),
  ).toBeVisible();
});

test('tablet chat composer fits when the visible viewport shrinks with the keyboard', async ({
  page,
}) => {
  await page.setViewportSize({ width: 828, height: 1160 });
  await setupAIRouteMocks(page);
  await enableAIForTesting(page);
  await before({ page });
  await openAISidebar(page);

  // Firefox Android may shrink innerHeight and visualViewport together,
  // leaving the keyboard inset at zero while CSS viewport units stay taller.
  await page.evaluate(() => {
    document.documentElement.style.setProperty('--keyboard-inset', '0px');
    document.documentElement.style.setProperty(
      '--visible-viewport-height',
      '810px',
    );
  });

  const panel = page.getByTestId('ai-sidebar');
  const composer = panel.getByTestId('assistant-file-dropzone');
  await expect
    .poll(async () => {
      const box = (await composer.boundingBox())!;

      return box.y + box.height;
    })
    .toBeLessThanOrEqual(810);
});

test('desktop AI chat keeps the composer inside the docked panel', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await setupAIRouteMocks(page);
  await page.route('https://openrouter.ai/api/v1/models**', route =>
    route.fulfill({
      json: {
        data: [
          {
            id: '~google/gemini-flash-latest',
            name: 'Gemini Flash',
            architecture: {
              input_modalities: ['text', 'image'],
              output_modalities: ['text'],
            },
            pricing: { prompt: 0, completion: 0 },
          },
          {
            id: 'test/alternate',
            name: 'Alternate model',
            architecture: {
              input_modalities: ['text'],
              output_modalities: ['text'],
            },
            pricing: { prompt: 0, completion: 0 },
          },
        ],
      },
    }),
  );
  await enableAIForTesting(page);
  await before({ page });
  await openAISidebar(page);
  const panel = page.getByTestId('ai-sidebar');
  const composer = panel.getByTestId('assistant-file-dropzone');
  await expect(composer).toBeVisible();
  await expect
    .poll(async () => {
      const box = (await composer.boundingBox())!;
      const panelBox = (await panel.boundingBox())!;

      return box.y + box.height - panelBox.y - panelBox.height;
    })
    .toBeLessThanOrEqual(0);
  await panel
    .getByRole('button', { name: 'AI Chat options', exact: true })
    .click();
  await expect(
    page.getByRole('combobox', { name: 'Model', exact: true }),
  ).toBeVisible();
  await page.getByRole('combobox', { name: 'Model', exact: true }).click();
  await page.getByRole('option', { name: /Alternate model/ }).click();
  await expect(
    page.getByRole('combobox', { name: 'Model', exact: true }),
  ).toHaveCount(0);
  await expect(composer.locator('[contenteditable="true"]')).toBeFocused();
  await panel
    .getByRole('button', { name: 'AI Chat options', exact: true })
    .click();
  await expect(
    page.getByRole('combobox', { name: 'Model', exact: true }),
  ).toHaveValue('Alternate model');
});

test('keyboard resize keeps the final sentence visible without a spacer above the composer', async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const ending = 'This final sentence must remain fully readable.';
  await setupScriptedToolCallMocks(
    page,
    [],
    Array(15)
      .fill(
        'A longer response fills the chat with useful information and several lines of text.',
      )
      .join('\n\n') +
      '\n\n' +
      ending,
  );
  await enableAIForTesting(page);
  await before({ page });
  await sendChatMessage(page, 'Give me a long answer');
  const panel = page.getByTestId('ai-sidebar');
  const lastLine = panel.getByText(ending, { exact: true });
  await expect(lastLine).toBeVisible();
  const viewport = panel.locator('[data-radix-scroll-area-viewport]');
  await viewport.evaluate(element => {
    element.scrollTop = element.scrollHeight;
  });
  await expect(lastLine).toBeInViewport();
  await page.evaluate(() =>
    document.documentElement.style.setProperty('--keyboard-inset', '320px'),
  );
  await expect
    .poll(async () => {
      const text = (await lastLine.boundingBox())!;
      const bounds = (await viewport.boundingBox())!;

      return text.y + text.height - bounds.y - bounds.height;
    })
    .toBeLessThanOrEqual(0);
  const composer = panel.getByTestId('assistant-file-dropzone');
  const bounds = (await viewport.boundingBox())!;
  expect(
    (await composer.boundingBox())!.y - bounds.y - bounds.height,
  ).toBeLessThanOrEqual(8);
  const finalText = (await lastLine.boundingBox())!;
  expect(
    (await composer.boundingBox())!.y - finalText.y - finalText.height,
  ).toBeLessThanOrEqual(16);
  await page.screenshot({ path: 'test-results/ai-mobile-long-keyboard.png' });
  // A reader scrolls by hand: the list only detaches after real input.
  await viewport.evaluate(element => {
    element.dispatchEvent(new WheelEvent('wheel', { bubbles: true }));
    element.scrollTop = 100;
  });
  await expect
    .poll(() => viewport.evaluate(element => element.scrollTop))
    .toBe(100);
  await page.evaluate(() =>
    document.documentElement.style.setProperty('--keyboard-inset', '240px'),
  );
  await expect
    .poll(() =>
      viewport.evaluate(
        element =>
          element.scrollHeight - element.clientHeight - element.scrollTop,
      ),
    )
    .toBeGreaterThan(100);
});

test('scrolling up right after the keyboard resize keeps the reading position', async ({
  page,
}) => {
  // The scroll handler used to treat any scroll within 150 ms of a resize as
  // the browser clamping, so a reader who scrolled up just after the keyboard
  // opened stayed attached and was pulled back down when the inset changed.
  await page.setViewportSize({ width: 390, height: 844 });
  const ending = 'This final sentence must remain fully readable.';
  await setupScriptedToolCallMocks(
    page,
    [],
    Array(15)
      .fill(
        'A longer response fills the chat with useful information and several lines of text.',
      )
      .join('\n\n') +
      '\n\n' +
      ending,
  );
  await enableAIForTesting(page);
  await before({ page });
  await sendChatMessage(page, 'Give me a long answer');
  const panel = page.getByTestId('ai-sidebar');
  await expect(panel.getByText(ending, { exact: true })).toBeVisible();
  const viewport = panel.locator('[data-radix-scroll-area-viewport]');
  await viewport.evaluate(element => {
    element.scrollTop = element.scrollHeight;
  });
  const lastLine = panel.getByText(ending, { exact: true });
  await page.evaluate(() =>
    document.documentElement.style.setProperty('--keyboard-inset', '320px'),
  );
  // Scroll as soon as the resize has been laid out, with nothing in between.
  await expect
    .poll(async () => {
      const text = (await lastLine.boundingBox())!;
      const bounds = (await viewport.boundingBox())!;

      return text.y + text.height - bounds.y - bounds.height;
    })
    .toBeLessThanOrEqual(0);
  // A reader scrolls by hand: the list only detaches after real input.
  await viewport.evaluate(element => {
    element.dispatchEvent(new WheelEvent('wheel', { bubbles: true }));
    element.scrollTop = 100;
  });
  await expect
    .poll(() => viewport.evaluate(element => element.scrollTop))
    .toBe(100);
  await page.evaluate(() =>
    document.documentElement.style.setProperty('--keyboard-inset', '240px'),
  );
  await expect
    .poll(() =>
      viewport.evaluate(
        element =>
          element.scrollHeight - element.clientHeight - element.scrollTop,
      ),
    )
    .toBeGreaterThan(100);
});

test('mobile chat keeps navigation usable and Back dismisses only the chat', async ({
  page,
}) => {
  await page.route('https://openrouter.ai/api/v1/credits', route =>
    route.fulfill({ json: { data: { total_credits: 10, total_usage: 1 } } }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await setupAIRouteMocks(page);
  await enableAIForTesting(page);
  await before({ page });
  const location = page.url();
  await openAISidebar(page);
  const panel = page.getByTestId('ai-sidebar');
  const editor = panel.locator('[contenteditable="true"]');
  await expect(editor).toBeVisible();
  await panel.getByRole('heading').click();
  await expect
    .poll(() =>
      editor.evaluate(element => {
        const wrapper = element.parentElement!.parentElement!;

        return wrapper.scrollHeight - wrapper.clientHeight;
      }),
    )
    .toBeLessThanOrEqual(1);

  await page.getByRole('button', { name: 'Show / hide sidebar' }).click();
  await expect(page.getByTestId('sidebar')).toBeVisible();
  await page.getByRole('button', { name: 'Show / hide sidebar' }).click();
  await panel.getByRole('button', { name: 'New Chat', exact: true }).click();
  await sendChatMessage(page, 'Hello from mobile');
  await expect(
    panel.getByText('This is a mock AI response.', { exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByTestId('ai-user-message').getByText('You', { exact: true }),
  ).toHaveCount(0);
  await page.goBack();
  await expect(panel).not.toHaveAttribute('data-open');
  expect(page.url()).toBe(location);

  await openAISidebar(page);
  await panel
    .getByRole('button', { name: 'AI Chat options', exact: true })
    .click();
  await expect(page.getByText('Agent', { exact: true })).toBeVisible();
  await expect(page.getByText('Model', { exact: true })).toBeVisible();
  await page.screenshot({
    path: 'test-results/mobile-ai-options.png',
    animations: 'disabled',
  });
  await page.getByRole('link', { name: 'AI settings', exact: true }).click();
  await expect(page).toHaveURL(/\/app\/settings\?section=ai/);
  await expect(panel).not.toHaveAttribute('data-open');
  await expect(
    page.getByRole('checkbox', { name: 'Enable AI Features' }),
  ).toBeVisible();
});

for (const { name, width, navigateAway } of [
  { name: 'mobile current resource', width: 390, navigateAway: false },
  { name: 'mobile different resource', width: 390, navigateAway: true },
  { name: 'desktop resource', width: 1280, navigateAway: true },
]) {
  test(`${name} links reveal the destination without losing chat`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 844 });
    await enableAIForTesting(page);
    await before({ page });
    const driveURL = page.url();
    const subject = await page.locator('main[about]').getAttribute('about');
    expect(subject).toBeTruthy();
    await setupAIRouteMocks(page, {
      chatResponse: `Here is your [linked drive](${subject}).`,
    });

    if (navigateAway) {
      const agent = await page.evaluate(
        () => window.store!.getAgent()!.subject,
      );
      if (!agent) throw new Error('Expected a signed-in agent');
      await page.goto(
        new URL(`/app/open?subject=${encodeURIComponent(agent)}`, driveURL)
          .href,
      );
    }

    await openAISidebar(page);
    await sendChatMessage(page, 'Show my drive');
    const panel = page.getByTestId('ai-sidebar');
    await panel
      .getByRole('link', { name: 'linked drive', exact: true })
      .click();
    await expect(page.locator('main[about]')).toHaveAttribute(
      'about',
      subject!,
    );

    if (width === 390) {
      await expect(panel).not.toHaveAttribute('data-open', '');
      await openAISidebar(page);
      await expect(
        panel.getByRole('link', { name: 'linked drive', exact: true }),
      ).toBeVisible();
    } else {
      await expect(panel).toHaveAttribute('data-open', '');
    }
  });
}

test('FOSS AI Chat options refreshes account credits without offering checkout', async ({
  page,
}) => {
  let remaining = 5_000_000;
  let statusRequests = 0;
  await enableAIForTesting(page);
  await setupAIRouteMocks(page);
  await before({ page });
  await page.route('https://portal.example/api/**', route => {
    const path = new URL(route.request().url()).pathname;

    if (path === '/api/ai/status') {
      statusRequests++;

      return route.fulfill({
        json: {
          enabled: true,
          consent: true,
          model: 'google/gemini-2.5-flash',
          paid: true,
          allowance_micros: 5_000_000,
          remaining_micros: remaining,
          used_micros: 5_000_000 - remaining,
          purchases_enabled: true,
          resets_at: 1790812800,
        },
      });
    }

    return route.fulfill({
      json: path === '/api/me' ? { email: 'credits@example.com' } : [],
    });
  });
  await page.addInitScript(() => {
    (
      window as Window & { __ATOMIC_MANAGED__?: { portalUrl: string } }
    ).__ATOMIC_MANAGED__ = { portalUrl: 'https://portal.example' };
    localStorage.removeItem('atomic.ai.openrouter-api-key');
  });
  await page.reload();
  await openAISidebar(page);
  const options = page.getByRole('button', {
    name: 'AI Chat options',
    exact: true,
  });
  await expect(options).toBeVisible();
  await expect.poll(() => statusRequests).toBeGreaterThan(0);
  await expect(page.getByText(/monthly credits left/)).toHaveCount(0);
  await expect(
    page.getByRole('link', { name: 'Get more credits' }),
  ).toHaveCount(0);
  remaining = 4_999_123;
  const beforeOpening = statusRequests;
  await options.click();
  await expect.poll(() => statusRequests).toBeGreaterThan(beforeOpening);
  await expect(
    page.getByText('4,999.123 of 5,000 monthly credits left'),
  ).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Get more credits' }),
  ).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(page.getByText(/monthly credits left/)).toHaveCount(0);
});
