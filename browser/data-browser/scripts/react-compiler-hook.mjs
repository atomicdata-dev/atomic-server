import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const hash = value => createHash('sha256').update(value).digest('hex');
const sourceDir = 'browser/data-browser/src/';

function feedback(message) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext: message,
    },
  };
}

export async function runHook(event, cacheRoot = tmpdir()) {
  if (event.hook_event_name !== 'PostToolUse') return;
  let cwd = event.cwd;
  const git = args =>
    execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 5000,
    });
  const root = realpathSync(git(['rev-parse', '--show-toplevel']).trim());
  cwd = root;
  // Both staged/unstaged changes and new files; don't parse shell commands or patches.
  const files = [
    ...new Set([
      ...git(['diff', 'HEAD', '--name-only', '-z', '--', sourceDir]).split(
        '\0',
      ),
      ...git([
        'ls-files',
        '--others',
        '--exclude-standard',
        '-z',
        '--',
        sourceDir,
      ]).split('\0'),
    ]),
  ].filter(
    file =>
      file.startsWith(sourceDir) &&
      /\.[jt]sx?$/.test(file) &&
      !/\.(?:test|spec|worker|d)\.[jt]sx?$/.test(file),
  );

  if (files.length === 0) return;
  const { checkSource, compilerVersion } = await import('./react-compiler.mjs');
  const cacheDir = join(cacheRoot, 'atomic-react-compiler-hooks');
  mkdirSync(cacheDir, { recursive: true });
  const cacheFile = join(
    cacheDir,
    `${hash(`${root}:${event.session_id ?? 'unknown'}`)}.json`,
  );
  let previous = {};

  try {
    previous = JSON.parse(readFileSync(cacheFile, 'utf8'));
  } catch {
    // A missing or interrupted cache is safe to rebuild.
  }

  const compilerHash = hash(
    readFileSync(new URL('./react-compiler.mjs', import.meta.url)),
  );
  const next = {};
  const diagnostics = [];

  for (const file of files) {
    const filename = join(root, file);
    let source;

    try {
      // Ignore deleted files and symlinks pointing outside the source tree.
      const real = realpathSync(filename);
      if (!relative(root, real).startsWith(sourceDir)) continue;
      source = readFileSync(real, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw error;
    }

    const fingerprint = hash(`${compilerVersion}:${compilerHash}:${source}`);
    next[file] = fingerprint;
    if (previous[file] === fingerprint) continue;
    diagnostics.push(...checkSource(filename, source).diagnostics);
  }

  // Atomic replace prevents readers seeing partially written JSON.
  const temporary = `${cacheFile}.${randomUUID()}.tmp`;
  writeFileSync(temporary, JSON.stringify(next));
  renameSync(temporary, cacheFile);

  if (diagnostics.length > 0) {
    return feedback(
      `React Compiler diagnostics in changed files (advisory; may include existing issues). Address regressions relevant to this task; no need to fix unrelated bailouts.\n${diagnostics.join('\n')}`,
    );
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const result = await runHook(JSON.parse(readFileSync(0, 'utf8')));
    if (result) console.info(JSON.stringify(result));
  } catch (error) {
    // Hook infrastructure failures inform the agent without blocking the edit.
    console.info(
      JSON.stringify(
        feedback(
          `React Compiler hook could not run: ${error.message.split('\n')[0]}`,
        ),
      ),
    );
  }
}
