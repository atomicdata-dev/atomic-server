import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
  readFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { runHook } from '../scripts/react-compiler-hook.mjs';
import { checkSource } from '../scripts/react-compiler.mjs';

const dir = realpathSync(mkdtempSync(join(tmpdir(), 'compiler-hook-test-')));
const root = join(dir, 'repo with spaces');
const src = join(root, 'browser/data-browser/src');
mkdirSync(src, { recursive: true });
const git = (...args) =>
  execFileSync('git', args, { cwd: root, stdio: 'pipe' });
git('init', '-q');
git(
  '-c',
  'user.name=Test',
  '-c',
  'user.email=test@example.com',
  'commit',
  '--allow-empty',
  '-qm',
  'Initial',
);
const clean = `import { useState } from 'react';
export function useExample() {
  const [value] = useState(0);
  return async () => { return value; };
}`;
const broken = clean.replace(
  'return value;',
  "try { if (value) { throw new Error('oops'); } return value; } catch { return 0; }",
);
const event = {
  hook_event_name: 'PostToolUse',
  tool_name: 'Bash',
  session_id: 'test',
  cwd: src,
};

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('React Compiler hook', () => {
  it('reports an untracked source, caches it, and rechecks changed content from a subdirectory', async () => {
    const filename = join(src, 'useExample.ts');
    writeFileSync(filename, broken);
    const output = await runHook(event, dir);
    expect(output.hookSpecificOutput.hookEventName).toBe('PostToolUse');
    expect(output.hookSpecificOutput.additionalContext).toContain(
      'useExample.ts:4:',
    );
    expect(output).not.toHaveProperty('decision');
    expect(await runHook(event, dir)).toBeUndefined();

    writeFileSync(filename, clean);
    expect(await runHook(event, dir)).toBeUndefined();
    writeFileSync(filename, broken);
    expect(await runHook(event, dir)).toBeDefined();
    // A fresh session receives its own diagnostics.
    expect(
      await runHook({ ...event, session_id: 'another' }, dir),
    ).toBeDefined();
    rmSync(filename);
    expect(await runHook(event, dir)).toBeUndefined();
  });

  it('finds staged files and ignores tests, workers and non-frontend files', async () => {
    writeFileSync(join(src, 'staged.ts'), broken);
    git('add', '.');
    writeFileSync(join(src, 'ignored.test.ts'), broken);
    writeFileSync(join(src, 'ignored.worker.ts'), broken);
    writeFileSync(join(root, 'outside.ts'), broken);
    const output = await runHook(event, dir);
    const context = output.hookSpecificOutput.additionalContext;
    expect(context).toContain('staged.ts');
    expect(context).not.toContain('ignored');
    expect(context).not.toContain('outside');
    rmSync(join(src, 'staged.ts'));
    expect(await runHook(event, dir)).toBeUndefined();
  });

  it('formats UTF-8 offsets as human line and column numbers', () => {
    const source = broken.replace('try {', '/* é 😀 */ try {');
    const line = source.split('\n')[3];
    const column = [...line.slice(0, line.indexOf('throw'))].length + 1;
    expect(checkSource('unicode.ts', source).diagnostics[0]).toMatch(
      new RegExp(`^unicode.ts:4:${column} — `),
    );
  });

  it('emits valid advisory JSON when invoked as a command', () => {
    writeFileSync(join(src, 'command.ts'), broken);
    const command = fileURLToPath(
      new URL('../scripts/react-compiler-hook.mjs', import.meta.url),
    );
    const result = spawnSync(process.execPath, [command], {
      input: JSON.stringify({ ...event, session_id: dir }),
      encoding: 'utf8',
      env: { ...process.env, TMPDIR: dir },
    });
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(
      JSON.parse(result.stdout).hookSpecificOutput.additionalContext,
    ).toContain('command.ts');
  });

  it('registers advisory checks for shell and patch tool calls', () => {
    const config = JSON.parse(
      readFileSync(
        new URL('../../../.codex/hooks.json', import.meta.url),
        'utf8',
      ),
    );
    const group = config.hooks.PostToolUse[0];
    expect('Bash').toMatch(new RegExp(group.matcher));
    expect('apply_patch').toMatch(new RegExp(group.matcher));
    expect(group.hooks[0].command).toContain('react-compiler-hook.mjs');
  });

  it('runs the Claude Code registration with advisory output and cached silence', () => {
    const config = JSON.parse(
      readFileSync(
        new URL('../../../.claude/settings.json', import.meta.url),
        'utf8',
      ),
    );
    const group = config.hooks.PostToolUse[0];

    for (const tool of ['Edit', 'Write', 'Bash']) {
      expect(tool).toMatch(new RegExp(group.matcher));
    }

    expect('Read').not.toMatch(new RegExp(group.matcher));

    const filename = join(src, 'claude.ts');
    writeFileSync(filename, broken);
    const invoke = () =>
      spawnSync(group.hooks[0].command, {
        shell: true,
        cwd: fileURLToPath(new URL('../', import.meta.url)),
        input: JSON.stringify({
          ...event,
          session_id: `claude-${dir}`,
          tool_name: 'Edit',
          tool_input: {
            file_path: filename,
            old_string: clean,
            new_string: broken,
          },
          tool_response: { filePath: filename, success: true },
        }),
        encoding: 'utf8',
        env: { ...process.env, TMPDIR: dir },
      });
    const result = invoke();
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    const output = JSON.parse(result.stdout);
    expect(output.hookSpecificOutput.hookEventName).toBe('PostToolUse');
    expect(output.hookSpecificOutput.additionalContext).toContain(
      'claude.ts:4:',
    );
    expect(output).not.toHaveProperty('decision');
    expect(invoke().stdout).toBe('');
  });
});
