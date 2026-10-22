// @wc-ignore-file
import { afterEach, describe, expect, it, vi } from 'vitest';
import { tool } from 'ai';
import { z } from 'zod';
import { TOOL_NAMES } from '../chunks/AI/useAtomicTools';
import {
  AI_READY_TIMEOUT_MS,
  aiCall,
  aiRunTool,
  aiToolList,
  EMBED_TOOL_DENYLIST,
  fillAgentPrompt,
  registerAiTools,
  withSearchFallback,
  type EmbedAiTool,
} from './aiTools';

const echo = tool({
  description: 'Echoes the text.',
  inputSchema: z.object({ text: z.string().describe('What to echo.') }),
  execute: async ({ text }) => ({ echoed: text }),
});

const fails = tool({
  description: 'Always fails.',
  inputSchema: z.object({}),
  execute: async (): Promise<string> => {
    throw new Error('boom');
  },
});

const says = tool({
  description: 'Gives text.',
  inputSchema: z.object({}),
  execute: async () => 'plain text',
});

let navigations = 0;
const navigates = tool({
  description: 'Moves the page.',
  inputSchema: z.object({}),
  execute: async () => {
    navigations++;

    return 'moved';
  },
});

function register(tools: Record<string, unknown>) {
  registerAiTools({
    tools: tools as Record<string, EmbedAiTool>,
    systemPrompt: async () => 'the prompt',
    uiEffects: () => navigations,
  });
}

afterEach(() => registerAiTools(undefined));

describe('aiToolList', () => {
  it('lists name, description and JSON schema, without denied tools', async () => {
    register({
      echo,
      says,
      navigate_to_resource: navigates,
      delete_resource: navigates,
    });

    const list = await aiToolList();

    expect(list.map(t => t.name)).toEqual(['echo', 'says']);

    const entry = list[0];

    expect(entry.description).toBe('Echoes the text.');
    expect(entry.parameters).toMatchObject({
      type: 'object',
      properties: { text: { type: 'string', description: 'What to echo.' } },
      required: ['text'],
    });
    // Plain JSON, as the app sends it on.
    expect(JSON.parse(JSON.stringify(list))).toEqual(list);
  });
});

describe('aiRunTool', () => {
  it('gives an object result as JSON and a text result as it is', async () => {
    register({ echo, says });

    expect(JSON.parse(await aiRunTool('echo', '{"text":"hi"}'))).toEqual({
      echoed: 'hi',
    });
    expect(await aiRunTool('says', '')).toBe('plain text');
  });

  it('answers {error} for unknown, denied, failing and malformed calls', async () => {
    register({ echo, fails, navigate_to_resource: navigates });

    const error = async (name: string, args: string) =>
      (JSON.parse(await aiRunTool(name, args)) as { error: string }).error;

    expect(await error('nope', '{}')).toMatch(/Unknown tool nope/);
    expect(await error('navigate_to_resource', '{}')).toMatch(/not available/);
    expect(await error('fails', '{}')).toBe('boom');
    expect(await error('echo', '{oops')).toMatch(/not valid JSON/);
    expect(await error('echo', '[1]')).toMatch(/JSON object/);
  });

  it('reports a tool that moved the page as failed', async () => {
    register({ moves: navigates });

    const result = JSON.parse(await aiRunTool('moves', '{}'));

    expect(result.error).toMatch(/open a page or dialog/);
  });

  it('answers {error} when no tools were ever registered', async () => {
    vi.useFakeTimers();

    const pending = aiRunTool('echo', '{}');

    await vi.advanceTimersByTimeAsync(AI_READY_TIMEOUT_MS + 1000);
    vi.useRealTimers();

    expect(JSON.parse(await pending).error).toMatch(/not available/);
  });
});

describe('aiCall', () => {
  it('posts the answer with the call id, and failures with ok: false', async () => {
    register({ echo });

    const posted: Record<string, unknown>[] = [];
    const post = (m: string) => posted.push(JSON.parse(m));

    await aiCall(post, 7, 'tools');
    await aiCall(post, 8, 'prompt');
    await aiCall(post, 9, 'run', ['echo', '{"text":"x"}']);
    await aiCall(post, 10, 'nope' as never);

    expect(posted.map(p => [p.method, p.callId, p.ok])).toEqual([
      ['aiResult', 7, true],
      ['aiResult', 8, true],
      ['aiResult', 9, true],
      ['aiResult', 10, false],
    ]);
    expect(JSON.parse(posted[0].payload as string)[0].name).toBe('echo');
    expect(posted[1].payload).toBe('the prompt');
    expect(JSON.parse(posted[2].payload as string)).toEqual({ echoed: 'x' });
  });
});

describe('the denylist', () => {
  it('only names tools the web chat has, each with a reason', () => {
    const names = new Set<string>(Object.values(TOOL_NAMES));

    for (const [name, why] of Object.entries(EMBED_TOOL_DENYLIST)) {
      expect(names.has(name), name).toBe(true);
      expect(why.length, name).toBeGreaterThan(10);
    }
  });
});

describe('fillAgentPrompt', () => {
  it('fills the placeholders as the web chat does and appends the skills', async () => {
    const prompt = await fillAgentPrompt(
      '{{timestamp}}|{{drive}}|{{custom-classes}}|{{drive-structure}}',
      {
        drive: 'did:ad:d',
        driveTree: async () => '- Home (#a)',
        customClasses: async () => [],
        now: new Date('2026-01-02T03:04:05Z'),
        skills: 'SKILLS',
      },
    );

    expect(prompt).toBe(
      '2026-01-02T03:04:05.000Z|did:ad:d|No custom classes found on the current drive.|- Home (#a)\n\nSKILLS',
    );
  });
});

describe('withSearchFallback', () => {
  it('searches locally where the semantic search fails', async () => {
    const wrapped = withSearchFallback(fails, async (q, limit) => [
      { subject: `s:${q}:${limit}`, title: 't', classes: 'c' },
    ]);

    expect(
      await (wrapped.execute as (i: unknown, o: unknown) => unknown)(
        { query: 'cat', limit: 3 },
        {},
      ),
    ).toEqual([{ subject: 's:cat:3', title: 't', classes: 'c' }]);
  });
});
