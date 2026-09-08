import { test, expect, type Page } from './fixtures';
import { before, FRONTEND_URL, newDrive, signIn } from './test-utils';
import {
  enableAIForTesting,
  setupScriptedToolCallMocks,
  type ScriptedToolCall,
} from './ai-mock';

/**
 * The assistant's table tools, exercised end to end: the LLM is scripted, but
 * the tools themselves really run against the store. This is the acceptance
 * test the plan asks for — could an assistant build and then *adapt* a mini-app
 * with only these tools?
 */

async function sendChatMessage(page: Page, text: string) {
  const sidebar = page.locator('[data-open]');
  const chatInput = sidebar.locator('[contenteditable="true"]');
  await expect(chatInput).toBeVisible({ timeout: 15_000 });

  // Vector indexing after drive creation disables Send.
  await sidebar
    .getByText('Indexing', { exact: true })
    .waitFor({ state: 'hidden', timeout: 30_000 })
    .catch(() => undefined);

  await chatInput.click();
  await page.keyboard.type(text);
  const sendButton = sidebar.getByTitle('Send');
  await expect(sendButton).toBeEnabled({ timeout: 30_000 });
  await sendButton.click();
}

/** The table subject out of a `create_table…` tool result. */
function tableFromResults(results: string[]): string {
  for (const result of results) {
    const match = /"table"\s*:\s*"([^"]+)"/.exec(result);

    if (match) {
      return match[1];
    }
  }

  throw new Error(`No table subject in tool results: ${results.join(' | ')}`);
}

test.describe('assistant table tools', () => {
  test('builds a table from a template, then adapts it', async ({ page }) => {
    test.slow();

    const script: ScriptedToolCall[] = [
      // 1. Start from the catalogue rather than re-deriving a schema.
      { tool: 'list_table_templates', args: {} },
      {
        tool: 'create_table_from_template',
        args: () => ({ template: 'time-tracker', name: 'Consulting hours' }),
      },
      // 2. Iterate: a column the template didn't have.
      {
        tool: 'add_table_columns',
        args: results => ({
          table: tableFromResults(results),
          columns: [{ name: 'Rate', type: 'number' }],
        }),
      },
      // 3. Configure a view in place: sort it, and total the new column.
      {
        tool: 'configure_view',
        args: results => ({
          table: tableFromResults(results),
          view: 'All entries',
          sortByColumn: 'Rate',
          sortDesc: true,
          aggregates: [{ function: 'sum', column: 'Rate' }],
        }),
      },
      // 4. Read the configuration back.
      {
        tool: 'describe_table',
        args: results => ({ table: tableFromResults(results) }),
      },
    ];

    const state = await setupScriptedToolCallMocks(
      page,
      script,
      'Built and adapted the table.',
    );

    await enableAIForTesting(page);
    await before({ page });
    await signIn(page);
    await newDrive(page);

    await sendChatMessage(page, 'Make me a timesheet and add a rate column');

    await expect(page.getByText('Built and adapted the table.')).toBeVisible({
      timeout: 60_000,
    });

    const results = state.toolResults.join('\n');

    // The template's own columns came along...
    expect(results).toContain('Project');
    // ...the added column exists and reported its subject...
    expect(results).toContain('Rate');
    // ...and describe_table read the view config back, including what the
    // configure_view call just set.
    expect(results).toContain('All entries');
    expect(results).toContain('sortBy');
    expect(results).toContain('aggregates');

    // And the table really is configured: open it and look. Addressed by subject
    // (the tool results carry shortened refs, and the sidebar lists lazily).
    const subject = await page.evaluate(() => {
      type StoredResource = {
        subject: string;
        get?: (property: string) => unknown;
      };
      let found = '';
      window.store.resources.forEach((resource: StoredResource) => {
        if (
          resource?.get?.('https://atomicdata.dev/properties/name') ===
          'Consulting hours'
        ) {
          found = resource.subject;
        }
      });

      return found;
    });
    expect(subject).not.toBe('');

    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(subject)}`,
    );
    await expect(page.getByRole('tab', { name: 'All entries' })).toBeVisible({
      timeout: 15_000,
    });
    await page.getByRole('tab', { name: 'All entries' }).click();

    await expect(
      page.getByRole('button', { name: 'Rate', exact: true }),
    ).toBeAttached({ timeout: 15_000 });
    // The total the assistant configured is rendered in the table's footer,
    // under the column it describes.
    await expect(page.getByTestId('table-totals')).toContainText('Sum', {
      timeout: 15_000,
    });
  });
});
