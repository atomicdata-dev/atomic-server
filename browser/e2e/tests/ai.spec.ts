import { isAtomicIdentifier } from '@tomic/lib';
import { test, expect } from './fixtures';
import { before, waitForSynced, reloadReconnected } from './test-utils';
import {
  AFTER_COMPACT_USER,
  AFTER_UNCOMPACT_USER,
  enableAIForTesting,
  FIRST_RESPONSE,
  FIRST_USER,
  sendChatMessage,
  setupAICompactMocks,
  setupAIRouteMocks,
  setupAIToolCallMocks,
} from './ai-mock';

const MOCK_RESPONSE = 'This is a mock AI response.';

test.describe('AI Chat', () => {
  test.beforeEach(async ({ page }) => {
    // Route mocks and init scripts must be registered before page.goto()
    await setupAIRouteMocks(page, { chatResponse: MOCK_RESPONSE });
    await enableAIForTesting(page);
    await before({ page });
  });

  test('sends a message and displays AI response', async ({ page }) => {
    await sendChatMessage(page, 'Hello AI');
    await expect(page.getByText(MOCK_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });
  });

  test('saves the chat and shows it in the AI Chats panel', async ({
    page,
  }) => {
    await sendChatMessage(page, 'Hello AI');
    await expect(page.getByText(MOCK_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });

    // AIPanel polls the search index after ResourceSaved until the new chat
    // shows up (see AIPanel.tsx's pollUntilIndexed), rather than waiting out
    // a fixed delay.
    await expect(
      page.getByTestId('sidebar').getByRole('link', { name: 'Test Chat' }),
    ).toBeVisible({ timeout: 15_000 });
  });

  test('persists a partial assistant reply before the stream finishes and restores it after refresh', async ({
    page,
    browserName,
    browserDiagnostics,
  }) => {
    const partial =
      'Your bakery website will use the existing products table. Prices stay in Atomic.';
    await page.evaluate(text => {
      const originalFetch = window.fetch.bind(window);

      window.fetch = async (input, init) => {
        if (
          String(input).includes('/chat/completions') &&
          JSON.parse(String(init?.body ?? '{}')).stream
        ) {
          const chunk = {
            id: 'checkpoint-test',
            object: 'chat.completion.chunk',
            model: 'test',
            choices: [
              {
                index: 0,
                delta: {
                  role: 'assistant',
                  content: text.replace(' Prices stay in Atomic.', ''),
                },
                finish_reason: null,
              },
            ],
          };

          return new Response(
            new ReadableStream({
              start(controller) {
                controller.enqueue(
                  new TextEncoder().encode(
                    `data: ${JSON.stringify(chunk)}\n\n`,
                  ),
                );
                setTimeout(() => {
                  chunk.choices[0].delta.content = ' Prices stay in Atomic.';
                  controller.enqueue(
                    new TextEncoder().encode(
                      `data: ${JSON.stringify(chunk)}\n\n`,
                    ),
                  );
                }, 2000);
                // Deliberately keep the response open: onFinish must never run.
              },
            }),
            { headers: { 'Content-Type': 'text/event-stream' } },
          );
        }

        return originalFetch(input, init);
      };
    }, partial);
    await sendChatMessage(page, 'Make my bakery a website');
    await expect(page.getByText(partial)).toBeVisible({ timeout: 15000 });
    const chatLink = page
      .getByTestId('sidebar')
      .getByRole('link', { name: 'Test Chat' });
    await expect(chatLink).toBeVisible({ timeout: 15000 });
    const href = await chatLink.getAttribute('href');
    const subject = isAtomicIdentifier(href!)
      ? href!
      : new URL(href!, page.url()).searchParams.get('subject')!;
    const chatUrl = new URL(
      '/app/show?subject=' + encodeURIComponent(subject),
      page.url(),
    ).href;
    // Messages are entries of the chat log pages under the chat.
    await expect
      .poll(
        async () =>
          page.evaluate(
            async ({ subject: subjectArg, partial: partialArg }) => {
              const store = window.store;
              const chat = await store.getResource(subjectArg);
              const children = await chat.getChildrenCollection();
              await children.waitForReady();
              let entries = 0;
              let found = false;

              for (let i = 0; i < children.totalMembers; i++) {
                const member = await children.getMemberWithIndex(i);
                const child = member
                  ? await store.getResource(member)
                  : undefined;

                if (
                  !child?.hasClasses('https://atomicdata.dev/classes/ChatLog')
                )
                  continue;

                for (const { entry } of child.listChatLogEntries()) {
                  entries++;
                  if (String(entry.parts).includes(partialArg)) found = true;
                }
              }

              return entries === 2 && found;
            },
            { subject, partial },
          ),
        { timeout: 15000 },
      )
      .toBe(true);
    await waitForSynced(page);
    await expect
      .poll(
        async () =>
          page.evaluate(
            async ({ subject: subjectArg, partial: partialArg }) => {
              const store = window.store;

              const read = async (id: string) => {
                // `client` is private. Reached the same way this block reaches
                // `_pendingGenesis` below, and on purpose: the point of the
                // poll is what the SERVER holds, not what this tab believes.
                const result = await store['client'].fetchResourceHTTP(id, {
                  signInfo: {
                    agent: store.getAgent()!,
                    serverURL: store.getServerUrl(),
                  },
                  serverURL: store.getServerUrl(),
                });

                if (result.resource.error) {
                  const local = await store.getResource(id);

                  throw new Error(
                    JSON.stringify({
                      missing: id,
                      classes: local.getClasses(),
                      saveState: store.getSaveState(local),
                      isNew: local.new,
                      pendingGenesis: !!local['_pendingGenesis'],
                      parent: local.get(
                        'https://atomicdata.dev/properties/parent',
                      ),
                    }),
                  );
                }

                return result.resource;
              };

              const chat = await store.getResource(subjectArg);
              const children = await chat.getChildrenCollection();
              await children.waitForReady();
              let entries = 0;
              let found = false;

              for (let i = 0; i < children.totalMembers; i++) {
                const member = await children.getMemberWithIndex(i);

                if (!member) continue;

                const logPage = await read(member);

                if (
                  !logPage.hasClasses('https://atomicdata.dev/classes/ChatLog')
                )
                  continue;

                for (const { entry } of logPage.listChatLogEntries()) {
                  entries++;
                  if (String(entry.parts).includes(partialArg)) found = true;
                }
              }

              return entries === 2 && found;
            },
            { subject, partial },
          ),
        { timeout: 15000 },
      )
      .toBe(true);

    if (browserName === 'firefox') {
      browserDiagnostics.expect(
        'warning',
        /^\[WS\] close code=1001 reason="" wasClean=true opened=true$/,
        'Firefox closes the active WebSocket when this test deliberately navigates away from a streaming chat.',
        1,
      );
    }

    await page.goto(chatUrl);
    await reloadReconnected(page);
    await expect(page.getByText(partial, { exact: true }).first()).toBeVisible({
      timeout: 15000,
    });
  });

  test('keeps received reasoning when the provider rate-limits the response', async ({
    page,
    browserDiagnostics,
    browserName,
  }) => {
    if (browserName !== 'firefox')
      browserDiagnostics.expect(
        'error',
        /429.*Rate limit test/,
        'The mock deliberately emits a provider rate-limit error.',
        1,
      );
    browserDiagnostics.expect(
      'error',
      /^AI request failed:/,
      'The interrupted request is reported to the user.',
      1,
    );
    const loggedProviderErrors: unknown[] = [];

    if (browserName === 'firefox') {
      browserDiagnostics.expect(
        'error',
        /^JSHandle@object$/,
        'Firefox also logs the mock 429 as an object; its code and message are asserted below.',
        1,
      );
      page.on('console', async msg => {
        if (msg.text() === 'JSHandle@object') {
          for (const arg of msg.args())
            loggedProviderErrors.push(
              await arg.evaluate(value => ({
                code: value?.code,
                message: value?.message,
              })),
            );
        }
      });
    }

    const reasoning =
      'I will reuse the existing product prices for the bakery website.';
    await page.evaluate(text => {
      const originalFetch = window.fetch.bind(window);

      window.fetch = async (input, init) => {
        if (
          String(input).includes('/chat/completions') &&
          JSON.parse(String(init?.body ?? '{}')).stream
        ) {
          return new Response(
            new ReadableStream({
              start(controller) {
                const chunk = {
                  id: 'rate-limit-test',
                  object: 'chat.completion.chunk',
                  model: 'test',
                  choices: [
                    {
                      index: 0,
                      delta: { role: 'assistant', reasoning: text },
                      finish_reason: null,
                    },
                  ],
                };
                controller.enqueue(
                  new TextEncoder().encode(
                    `data: ${JSON.stringify(chunk)}\n\n`,
                  ),
                );
                setTimeout(() => {
                  controller.enqueue(
                    new TextEncoder().encode(
                      `data: ${JSON.stringify({ error: { code: 429, message: 'Rate limit test' } })}\n\ndata: [DONE]\n\n`,
                    ),
                  );
                  controller.close();
                }, 1500);
              },
            }),
            { headers: { 'Content-Type': 'text/event-stream' } },
          );
        }

        return originalFetch(input, init);
      };
    }, reasoning);
    await sendChatMessage(page, 'Make my bakery a website');
    await expect(page.getByText(reasoning, { exact: true })).toBeVisible({
      timeout: 15000,
    });
    await expect(page.getByText(/No answer from OpenRouter/)).toBeVisible({
      timeout: 15000,
    });
    if (browserName === 'firefox')
      await expect
        .poll(() => loggedProviderErrors)
        .toEqual([{ code: 429, message: 'Rate limit test' }]);
    // Error handling must leave the already received reasoning available.
    await expect(page.getByText(reasoning, { exact: true })).toBeVisible();
    const chatLink = page
      .getByTestId('sidebar')
      .getByRole('link', { name: 'Test Chat' });
    await expect(chatLink).toBeVisible();
    const href = await chatLink.getAttribute('href');
    const subject = isAtomicIdentifier(href!)
      ? href!
      : new URL(href!, page.url()).searchParams.get('subject')!;
    await waitForSynced(page);
    if (browserName === 'firefox')
      browserDiagnostics.expect(
        'warning',
        /^\[WS\] close code=1001 reason="" wasClean=true opened=true$/,
        'Firefox closes the WebSocket when this test navigates away from the interrupted chat.',
        1,
      );
    await page.goto(
      new URL('/app/show?subject=' + encodeURIComponent(subject), page.url())
        .href,
    );
    await reloadReconnected(page);
    await expect(
      page.getByText(reasoning, { exact: true }).first(),
    ).toBeVisible();
    await expect(
      page.getByRole('alert').filter({ hasText: 'Rate limit test' }).first(),
    ).toBeVisible();
  });

  test('new chat button clears the conversation', async ({ page }) => {
    await sendChatMessage(page, 'Hello AI');
    await expect(page.getByText(MOCK_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });

    await page
      .getByTestId('ai-sidebar')
      .getByRole('button', { name: 'New Chat' })
      .click();
    await expect(page.getByText(MOCK_RESPONSE)).not.toBeVisible();
  });
});

test.describe('AI Tools', () => {
  // Shared across beforeEach and test body; safe because tests run serially.
  let toolState: Awaited<ReturnType<typeof setupAIToolCallMocks>>;

  test.beforeEach(async ({ page }) => {
    // setupAIToolCallMocks registers route intercepts including /models which
    // fires on page load — must be called before before() / page.goto().
    toolState = await setupAIToolCallMocks(page);
    await enableAIForTesting(page);
    await before({ page });
  });

  test('tool calls create/edit/read a resource and show the review UI', async ({
    page,
  }) => {
    toolState.driveUrl = await page.evaluate(() => window.store.getDrive()!);

    await sendChatMessage(
      page,
      'Create a resource, edit it, then read it back',
    );

    // Each tool call renders a message bubble in the chat as it executes.
    // The create_resource title is parsed from the jsonAD name property.
    await expect(
      page.getByText('Creating AI Test Bookmark').first(),
    ).toBeVisible({ timeout: 15_000 });

    // edit_atomic_resource shows the property title and resource name.
    await expect(
      page.getByText(/Editing.*AI Test Bookmark/).first(),
    ).toBeVisible({ timeout: 10_000 });

    // get_atomic_resource shows "Reading <resource title>".
    await expect(
      page.getByText(/Reading.*AI Test Bookmark/).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Wait for the full tool-call chain to complete and the final text to appear.
    await expect(
      page.getByText('Done! I created, edited, and read back the resource.'),
    ).toBeVisible({ timeout: 30_000 });

    // edit_atomic_resource calls onResourceEdited → reportAIEdit → floating button.
    const reviewButton = page.getByRole('button', { name: /Review \d+ edit/ });
    await expect(reviewButton).toBeVisible({ timeout: 10_000 });

    // Open the review dialog.
    await reviewButton.click();
    await expect(
      page.getByRole('heading', { name: 'Review Edits' }),
    ).toBeVisible();

    // Confirm the changes — saves the resource and dismisses the dialog.
    await page.getByTitle('Confirm Changes').click();
    await expect(
      page.getByRole('heading', { name: 'Review Edits' }),
    ).not.toBeVisible();
  });
});

test.describe('AI Compacting', () => {
  test.beforeEach(async ({ page }) => {
    await setupAICompactMocks(page);
    await enableAIForTesting(page);
    await page.addInitScript(() => {
      localStorage.setItem(
        'atomic.ai.showFollowUpPrompts',
        JSON.stringify(false),
      );
    });
    await before({ page });
  });

  test('manual /compact trims context sent to the model', async ({ page }) => {
    test.setTimeout(180_000);

    const sendTimeout = 120_000;

    await sendChatMessage(page, FIRST_USER, { timeout: sendTimeout });
    await expect(page.getByText(FIRST_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });

    await sendChatMessage(page, '/compact', { timeout: sendTimeout });
    await expect(page.getByText('Context compacted')).toBeVisible({
      timeout: 15_000,
    });

    await sendChatMessage(page, AFTER_COMPACT_USER, { timeout: sendTimeout });
    await expect(page.getByText('Compact context OK')).toBeVisible({
      timeout: 15_000,
    });

    const sidebar = page.getByTestId('ai-sidebar');
    const summaryMessageRow = sidebar.locator('[data-summary-message]');
    await summaryMessageRow.hover();
    await summaryMessageRow.getByTitle('Delete Message').click();
    await expect(page.getByText('Context compacted')).not.toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByText(FIRST_USER)).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(FIRST_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });

    await sendChatMessage(page, AFTER_UNCOMPACT_USER, { timeout: sendTimeout });
    await expect(page.getByText('Uncompact context OK')).toBeVisible({
      timeout: 15_000,
    });
  });
});
