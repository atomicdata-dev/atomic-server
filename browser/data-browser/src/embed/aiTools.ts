// @wc-ignore-file
/**
 * The web app's AI tools, offered to the Flutter app's own AI chat.
 *
 * The app's chat talks to the account's model itself, but the tools it gives
 * the model are this page's: the same names, descriptions, input schemas and
 * implementations as the web chat (`useAtomicMCPTools`), and the same system
 * prompt. A page loaded with `?ai=1` mounts `AiToolsHost`, which builds them
 * with the web app's hooks and registers them here ({@link registerAiTools}).
 * The app then asks through `window.atomicEmbed`:
 *
 *   aiToolList()               [{name, description, parameters}]
 *   aiSystemPrompt()           the web chat's prompt for the current drive
 *   aiRunTool(name, argsJson)  the tool's result, as the chat feeds the model
 *   aiCall(id, method, args)   one of these, answered on the app's channel:
 *                              `{method:'aiResult', callId, ok, payload}`
 *
 * Tools that need the web app's own screen are left out ({@link
 * EMBED_TOOL_DENYLIST}): the app has no page to navigate, no dialog to open.
 */
import { asSchema } from 'ai';

/** What the page needs of an AI SDK tool. */
export interface EmbedAiTool {
  description?: string;
  inputSchema?: unknown;
  execute?: (input: never, options: never) => unknown;
}

export interface AiToolDescription {
  name: string;
  description: string;
  /** JSON Schema of the tool's input. */
  parameters: Record<string, unknown>;
}

/**
 * Tools of the web chat that are not offered in the app, and why. A name here
 * is dropped from the list and refused when called.
 */
export const EMBED_TOOL_DENYLIST: Record<string, string> = {
  navigate_to_resource:
    'Navigates the web app to a page; the app has no such page to move.',
  open_share_settings:
    'Runs a resource action that navigates to the share settings page.',
  show_history: 'Runs a resource action that navigates to the history page.',
  favorite_resource:
    'Needs the resource ActionContext and keeps favorites in the web view’s own storage, which the app does not read.',
  delete_resource:
    'Needs the resource ActionContext and confirms with a dialog in the web app; permanent deletes are not done without one.',
  setup_app:
    'Opens the app-setup form (a dialog) for the person to complete; the app has none.',
  list_app_setups: 'Only describes what setup_app opens; useless without it.',
  edit_document_resource:
    'Runs a second model call through the web app’s own AI settings (model, key); the app’s account AI is not wired into the page.',
  create_skill:
    'Saves a skill in the web view’s local storage, which the app never reads back.',
  discover_integrations:
    'Reads integrations from a server; the page has no server (host-backed store).',
  list_integration_actions: 'Needs a server connection; the page has none.',
  call_integration_action: 'Needs a server connection; the page has none.',
  create_plugin: 'Needs a server (plugin runs); the page has none.',
  run_plugin: 'Needs a server (plugin runs); the page has none.',
  schedule_plugin: 'Needs a server (plugin runs); the page has none.',
};

/** The tools and the prompt the page offers, set by `AiToolsHost`. */
export interface AiToolsSource {
  tools: Record<string, EmbedAiTool>;
  /** The system prompt for the current drive. */
  systemPrompt(): Promise<string>;
  /**
   * Tells how many times the page navigated (or opened a dialog) so far: a
   * tool that did is reported as failed (see {@link aiRunTool}).
   */
  uiEffects?(): number;
}

let source: AiToolsSource | undefined;
let waiting: ((s: AiToolsSource) => void)[] = [];
let calls = 0;

/** Makes [next] the page's tools (replacing the earlier ones). */
export function registerAiTools(next: AiToolsSource | undefined): void {
  source = next;

  if (next) {
    const pending = waiting;

    waiting = [];
    pending.forEach(resolve => resolve(next));
  }
}

/** How long a call waits for the host component to mount. */
export const AI_READY_TIMEOUT_MS = 15_000;

function ready(): Promise<AiToolsSource> {
  if (source) return Promise.resolve(source);

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      waiting = waiting.filter(w => w !== done);
      reject(new Error('The AI tools are not available in this page.'));
    }, AI_READY_TIMEOUT_MS);

    const done = (s: AiToolsSource) => {
      clearTimeout(timer);
      resolve(s);
    };

    waiting.push(done);
  });
}

const offered = (s: AiToolsSource): [string, EmbedAiTool][] =>
  Object.entries(s.tools).filter(
    ([name, t]) => !(name in EMBED_TOOL_DENYLIST) && !!t.execute,
  );

function schemaOf(tool: EmbedAiTool): Record<string, unknown> {
  try {
    const json = asSchema(tool.inputSchema as never).jsonSchema as Record<
      string,
      unknown
    >;

    return json && typeof json === 'object'
      ? json
      : { type: 'object', properties: {} };
  } catch {
    return { type: 'object', properties: {} };
  }
}

/** The tools the app may give the model. */
export async function aiToolList(): Promise<AiToolDescription[]> {
  const s = await ready();

  return offered(s).map(([name, t]) => ({
    name,
    description: t.description ?? '',
    parameters: schemaOf(t),
  }));
}

/** The web chat's system prompt, for the current drive. */
export async function aiSystemPrompt(): Promise<string> {
  return (await ready()).systemPrompt();
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** What the chat feeds the model for [output]: text as it is, the rest JSON. */
const serialise = (output: unknown): string =>
  typeof output === 'string' ? output : (JSON.stringify(output) ?? 'null');

/**
 * Runs [name] with [argsJson] (a JSON object) and gives its result as text.
 * Never throws: an unknown or refused tool, bad arguments, a failure in the
 * tool, and a tool that tried to move the page all give `{"error": message}`.
 */
export async function aiRunTool(
  name: string,
  argsJson: string,
): Promise<string> {
  try {
    if (name in EMBED_TOOL_DENYLIST) {
      throw new Error(`The tool ${name} is not available in the app.`);
    }

    const s = await ready();
    const tool = s.tools[name];

    if (!tool?.execute) throw new Error(`Unknown tool ${name}.`);

    let args: unknown = {};

    if (argsJson.trim()) {
      try {
        args = JSON.parse(argsJson);
      } catch (e) {
        throw new Error(`The arguments are not valid JSON: ${message(e)}`);
      }
    }

    if (args === null || typeof args !== 'object' || Array.isArray(args)) {
      throw new Error('The arguments must be a JSON object.');
    }

    const before = s.uiEffects?.() ?? 0;
    const output = await tool.execute(
      args as never,
      {
        toolCallId: `app-${++calls}`,
        messages: [],
      } as never,
    );

    if ((s.uiEffects?.() ?? 0) !== before) {
      throw new Error(
        `The tool ${name} tried to open a page or dialog, which the app cannot show.`,
      );
    }

    return serialise(output);
  } catch (e) {
    return JSON.stringify({ error: message(e) });
  }
}

/**
 * Answers an async call of the app on its channel: `fn` runs, and its result
 * (or failure) goes back as `{method:'aiResult', callId, ok, payload}`, as
 * `runJavaScript` does not wait for a promise.
 */
export async function aiCall(
  post: (message: string) => void,
  callId: number,
  method: 'tools' | 'prompt' | 'run',
  args: unknown[] = [],
): Promise<void> {
  let ok = true;
  let payload: string;

  try {
    switch (method) {
      case 'tools':
        payload = JSON.stringify(await aiToolList());
        break;
      case 'prompt':
        payload = await aiSystemPrompt();
        break;
      case 'run':
        payload = await aiRunTool(String(args[0]), String(args[1] ?? ''));
        break;
      default:
        throw new Error(`Unknown AI call ${String(method)}`);
    }
  } catch (e) {
    ok = false;
    payload = message(e);
  }

  post(JSON.stringify({ method: 'aiResult', callId, ok, payload }));
}

/** What the web chat fills into its system prompt (`ClientOnlyTransport`). */
export interface PromptValues {
  drive: string;
  /** The drive's tree, `- title (ref)` lines; read only if the prompt wants it. */
  driveTree: () => Promise<string>;
  /** The drive's custom classes, `title: ref` lines. */
  customClasses: () => Promise<string[]>;
  now: Date;
  /** Appended after the prompt: the list of skills. */
  skills?: string;
}

/**
 * The web chat's system prompt from its template: the same placeholders
 * replaced the same way (`prepareSystemPrompt` in `ClientOnlyTransport`).
 */
export async function fillAgentPrompt(
  template: string,
  values: PromptValues,
): Promise<string> {
  let prompt = template.replaceAll('{{drive}}', values.drive);

  if (prompt.includes('{{drive-structure}}')) {
    prompt = prompt.replaceAll('{{drive-structure}}', await values.driveTree());
  }

  if (prompt.includes('{{custom-classes}}')) {
    const classes = await values.customClasses();

    prompt = prompt.replaceAll(
      '{{custom-classes}}',
      classes.length === 0
        ? 'No custom classes found on the current drive.'
        : classes.join('\n'),
    );
  }

  prompt = prompt.replaceAll('{{timestamp}}', values.now.toISOString());

  return values.skills ? `${prompt}\n\n${values.skills}` : prompt;
}

/**
 * Semantic search needs a server with embeddings; the page has none. Where
 * the web tool fails, [search] (the app's own full-text search of the drive)
 * answers in the same shape, without chunks.
 */
export function withSearchFallback(
  tool: EmbedAiTool,
  search: (
    query: string,
    limit: number,
  ) => Promise<{ subject: string; title: string; classes: string }[]>,
): EmbedAiTool {
  const execute = tool.execute as (i: never, o: never) => Promise<unknown>;

  return {
    ...tool,
    execute: async (input: never, options: never) => {
      try {
        return await execute(input, options);
      } catch {
        const { query, limit } = input as { query?: string; limit?: number };

        return search(String(query ?? ''), limit ?? 10);
      }
    },
  };
}
