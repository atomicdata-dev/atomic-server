import { test, expect } from './fixtures';
import { before } from './test-utils';
import {
  enableAIForTesting,
  openAISidebar,
  setupAIRouteMocks,
} from './ai-mock';

test('AI configuration lives in Settings and persists agent, skill and MCP edits', async ({
  page,
  browserDiagnostics,
}) => {
  browserDiagnostics.expect(
    'error',
    /Cannot update a component.*AppSettingsContextProvider DrivePage DrivePage/,
    'Existing DrivePage settings warning.',
    1,
    undefined,
    { optional: true },
  );
  await page.route('https://mcp.example.test/**', async route => {
    const body = route.request().postDataJSON();

    if (!body?.id) {
      await route.fulfill({ status: 202 });

      return;
    }

    await route.fulfill({
      json: {
        jsonrpc: '2.0',
        id: body.id,
        result:
          body.method === 'initialize'
            ? {
                protocolVersion: '2025-03-26',
                capabilities: { tools: {} },
                serverInfo: { name: 'test', version: '1' },
              }
            : { tools: [] },
      },
    });
  });
  await page.route('http://localhost:11434/api/tags', route =>
    route.fulfill({ json: { models: [] } }),
  );
  await setupAIRouteMocks(page);
  await enableAIForTesting(page);
  await page.route('https://openrouter.ai/api/v1/credits**', route =>
    route.fulfill({ json: { data: { total_credits: 100, total_usage: 0 } } }),
  );
  await page.route('https://openrouter.ai/api/v1/models**', route =>
    route.fulfill({
      json: {
        data: [
          {
            id: '~google/gemini-flash-latest',
            name: 'Gemini Flash',
            description: '',
            supported_parameters: ['tools'],
            pricing: { prompt: 0, completion: 0 },
            architecture: {
              input_modalities: ['text'],
              output_modalities: ['text'],
            },
          },
          {
            id: 'test/alternate',
            name: 'Alternate model',
            description: '',
            created: 1756684800,
            supported_parameters: ['tools'],
            pricing: { prompt: 0, completion: 0 },
            architecture: {
              input_modalities: ['text'],
              output_modalities: ['text'],
            },
          },
        ],
      },
    }),
  );
  await page.route(
    'https://openrouter.ai/api/v1/models?output_modalities=transcription',
    route =>
      route.fulfill({
        json: {
          data: [
            { id: 'openai/whisper-1', name: 'Whisper 1' },
            { id: 'openai/whisper-large-v3', name: 'Whisper Large V3' },
          ],
        },
      }),
  );
  await page.route('https://openrouter.ai/api/v1/endpoints/zdr', route =>
    route.fulfill({ json: { data: [{ model_id: 'test/alternate' }] } }),
  );
  await before({ page });
  await openAISidebar(page);
  await page
    .getByRole('button', { name: 'AI Chat options', exact: true })
    .click();
  await page
    .getByRole('combobox', { name: 'Chat agent' })
    .selectOption('settings');
  await expect(page).toHaveURL(/\/app\/settings\?q=ai/);
  await expect(
    page.getByRole('heading', { name: 'Settings', exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(
    page.getByRole('main').getByRole('tablist', { name: 'Provider' }),
  ).toHaveCount(0);
  await expect(
    page.getByText('Default chat model', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByLabel('OpenRouter API Key', { exact: true }),
  ).toHaveValue('test-e2e-key');
  await expect(page.getByLabel('Ollama API Url')).toBeVisible();
  await page
    .getByRole('checkbox', { name: 'No data retention', exact: true })
    .first()
    .check();
  await expect(
    page.getByText('1 Models', { exact: true }).first(),
  ).toBeVisible();
  const modelInput = page
    .getByText('Default chat model', { exact: true })
    .locator('..')
    .getByRole('combobox');
  // fill() can type below the viewport. Bring the control into view as a
  // person would before opening its positioned suggestion list.
  await modelInput.click();
  await modelInput.fill('Gemini');
  await expect(
    page.getByRole('option', { name: 'Gemini Flash', exact: true }),
  ).toHaveCount(0);
  await modelInput.fill('Alternate');
  const inputWidth = await modelInput.evaluate(
    input => input.parentElement!.getBoundingClientRect().width,
  );
  await expect
    .poll(async () => (await page.getByRole('listbox').boundingBox())?.width)
    .toBeCloseTo(inputWidth, 0);
  await expect(
    page.getByRole('option', { name: /^Alternate model/ }),
  ).toContainText('from $0.00/M input · $0.00/M output · added Sept 2025');
  await page.screenshot({ path: '/tmp/atomic-model-dropdown.png' });
  await page.getByRole('option', { name: /^Alternate model/ }).click();
  expect(
    await page.evaluate(() =>
      JSON.parse(localStorage.getItem('atomic.ai.defaultChatModel')!),
    ),
  ).toEqual({ id: 'test/alternate', provider: 'openrouter' });

  await page
    .getByLabel('Transcription model', { exact: true })
    .selectOption('openai/whisper-large-v3');
  await page
    .getByRole('checkbox', { name: 'Enable voice input', exact: true })
    .uncheck();
  await expect(
    page.getByRole('button', { name: 'Start voice message', exact: true }),
  ).toHaveCount(0);
  await page.reload();
  await expect(
    page.getByRole('checkbox', { name: 'Enable voice input', exact: true }),
  ).not.toBeChecked();
  await page
    .getByRole('checkbox', { name: 'Enable voice input', exact: true })
    .check();
  await expect(
    page.getByLabel('Transcription model', { exact: true }),
  ).toHaveValue('openai/whisper-large-v3');
  await page
    .getByLabel('Transcription model', { exact: true })
    .scrollIntoViewIfNeeded();
  await page.screenshot({ path: '/tmp/atomic-speech-settings.png' });
  // Agents, skills and MCP servers are listed on the settings page, but
  // created and edited in a dialog.
  const editorDialog = page.getByRole('dialog');

  await page
    .getByRole('button', { name: 'Create New Agent', exact: true })
    .click();
  await expect(
    editorDialog.getByRole('heading', { name: 'New Agent', exact: true }),
  ).toBeVisible();
  await expect(
    editorDialog.getByRole('button', { name: 'Create Agent', exact: true }),
  ).toBeDisabled();
  await editorDialog
    .getByRole('textbox', { name: /^Name/ })
    .fill('Settings test agent');
  await editorDialog
    .getByRole('button', { name: 'Create Agent', exact: true })
    .click();
  await expect(editorDialog).toHaveCount(0);
  await expect(
    page.getByRole('radio', { name: 'Settings test agent', exact: true }),
  ).toBeChecked();

  await page
    .getByRole('button', { name: 'Create New Skill', exact: true })
    .click();
  await editorDialog
    .getByRole('textbox', { name: /^Name/ })
    .fill('settings-test-skill');
  await editorDialog
    .getByRole('textbox', { name: /^Description/ })
    .fill('A skill saved from Settings');
  await editorDialog
    .getByRole('button', { name: 'Create Skill', exact: true })
    .click();
  await expect(editorDialog).toHaveCount(0);
  await expect(
    page.getByText('settings-test-skill', { exact: true }),
  ).toBeVisible();

  // Cancelling an edit leaves the saved skill untouched.
  await page.getByRole('button', { name: 'Edit Skill', exact: true }).click();
  await expect(
    editorDialog.getByRole('heading', { name: 'Edit Skill', exact: true }),
  ).toBeVisible();
  await editorDialog
    .getByRole('textbox', { name: /^Description/ })
    .fill('Discarded description');
  await editorDialog
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  await expect(editorDialog).toHaveCount(0);
  await expect(
    page.getByText('A skill saved from Settings', { exact: true }),
  ).toBeVisible();

  await page
    .getByRole('button', { name: 'Add New Server', exact: true })
    .click();
  await editorDialog
    .getByRole('textbox', { name: /^Name/ })
    .fill('Settings test MCP');
  await editorDialog
    .getByRole('textbox', { name: /^URL/ })
    .fill('https://mcp.example.test');
  await editorDialog
    .getByRole('button', { name: 'Create Server', exact: true })
    .click();
  await expect(editorDialog).toHaveCount(0);
  await expect(
    page.getByText('Settings test MCP', { exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole('radio', { name: 'Settings test agent', exact: true }),
  ).toBeChecked();
  await expect(
    page.getByText('settings-test-skill', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText('Settings test MCP', { exact: true }),
  ).toBeVisible();
  await page.getByPlaceholder('Search settings...').fill('skills');
  await expect(
    page.getByRole('button', { name: 'Create New Skill', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Create New Agent', exact: true }),
  ).toHaveCount(0);
  await page.getByPlaceholder('Search settings...').fill('titles');
  await expect(
    page.getByRole('checkbox', {
      name: 'Generate AI Chat titles',
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByLabel('OpenRouter API Key', { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('checkbox', {
      name: 'Show follow up prompts in chats',
      exact: true,
    }),
  ).toHaveCount(0);
  await page.getByPlaceholder('Search settings...').fill('API');
  await expect(
    page.getByLabel('OpenRouter API Key', { exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel('Ollama API Url')).toBeVisible();
  await expect(
    page.getByText('Default chat model', { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('checkbox', {
      name: 'Generate AI Chat titles',
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('checkbox', { name: 'Enable voice input', exact: true }),
  ).toHaveCount(0);
  await page.screenshot({ path: '/tmp/atomic-settings-api-search.png' });
  await page.getByPlaceholder('Search settings...').fill('ai');
  await page
    .getByText('Default chat model', { exact: true })
    .scrollIntoViewIfNeeded();
  await expect(page.getByRole('main').getByRole('tablist')).toHaveCount(0);
  await page
    .getByRole('combobox', { name: 'Provider', exact: true })
    .selectOption('ollama');
  await expect(
    page.getByText('Ollama URL is not configured.', { exact: false }),
  ).toBeVisible();
  await page
    .getByRole('combobox', { name: 'Provider', exact: true })
    .selectOption('openrouter');
  await page
    .getByRole('combobox', { name: 'Provider', exact: true })
    .scrollIntoViewIfNeeded();
  await page.screenshot({ path: '/tmp/atomic-generative-model.png' });
  await page.getByPlaceholder('Search settings...').fill('');
  await expect(
    page.getByRole('combobox', { name: 'Provider', exact: true }),
  ).toHaveCount(0);
  await page.getByRole('main').getByText('AI', { exact: true }).click();
  const labels = [
    'Generative features',
    'OpenRouter',
    'Ollama',
    'Speech-to-text',
    'Agents',
    'Skills',
    'MCP',
  ];
  const boxes = await Promise.all(
    labels.map(label =>
      page.getByRole('main').getByText(label, { exact: true }).boundingBox(),
    ),
  );

  for (let i = 1; i < boxes.length; i++) {
    expect(boxes[i]!.x).toBeCloseTo(boxes[0]!.x, 0);
    if (i > 1)
      expect(boxes[i]!.y - boxes[i - 1]!.y).toBeCloseTo(
        boxes[1]!.y - boxes[0]!.y,
        0,
      );
  }

  await page
    .getByRole('main')
    .getByText('Integration', { exact: true })
    .scrollIntoViewIfNeeded();
  await page.screenshot({ path: '/tmp/atomic-settings-uniform.png' });
});
