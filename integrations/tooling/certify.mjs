import {
  readdirSync,
  readFileSync,
  mkdirSync,
  writeFileSync,
  existsSync,
} from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export function discover(base = root) {
  return readdirSync(resolve(base, 'integrations'), { withFileTypes: true })
    .filter(
      d =>
        d.isDirectory() &&
        existsSync(resolve(base, 'integrations', d.name, 'package.json')),
    )
    .map(d => {
      const path = `integrations/${d.name}`;
      const pkg = JSON.parse(
        readFileSync(resolve(base, path, 'package.json'), 'utf8'),
      );
      const c = pkg.atomicCertification;
      if (
        !c ||
        typeof c.owner !== 'string' ||
        !c.owner.trim() ||
        typeof c.apiVersion !== 'string' ||
        !c.apiVersion ||
        !['experimental', 'partner-supported', 'atomic-supported'].includes(
          c.support,
        ) ||
        typeof pkg.version !== 'string' ||
        !Array.isArray(c.capabilities) ||
        !c.capabilities.length ||
        !c.capabilities.every(v => typeof v === 'string' && v.length > 0) ||
        !Array.isArray(c.sandboxTests) ||
        !c.sandboxTests.length
      )
        throw new Error(`${path}: missing certification metadata`);
      if (
        !c.sandboxTests.every(
          t => typeof t === 'string' && /^plugins(?:::[a-z_]+){2,}$/.test(t),
        )
      )
        throw new Error(`${path}: invalid sandbox test name`);
      for (const file of [
        'plugin.ts',
        'plugin.js',
        'tsconfig.json',
        'vitest.config.ts',
        'README.md',
      ])
        if (!existsSync(resolve(base, path, file)))
          throw new Error(`${path}: missing ${file}`);
      return {
        id: d.name,
        path,
        version: pkg.version,
        owner: c.owner,
        support: c.support,
        apiVersion: c.apiVersion,
        capabilities: c.capabilities,
        sandboxTests: c.sandboxTests,
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
}
export function evaluateJs(report) {
  return (
    report.success === true &&
    report.numPassedTests > 0 &&
    report.numFailedTests === 0
  );
}
export function evaluateRust(output) {
  return /test result: ok\. 1 passed; 0 failed; 0 ignored;/.test(output);
}
export function summarizeFailure({ error, stderr, stdout }) {
  const line = [error, stderr, stdout]
    .flatMap(value => String(value ?? '').split(/\r?\n/))
    .map(value => value.trim())
    .find(Boolean);
  if (!line) return 'command failed without output';
  return line.length > 240 ? `${line.slice(0, 237)}...` : line;
}
export function formatFailureSummary(checks) {
  return checks
    .filter(check => check.status === 'failed')
    .map(check =>
      check.detail ? `${check.name}: ${check.detail}` : check.name,
    )
    .join('; ');
}
export function certify({
  layer = 'all',
  output = resolve(root, 'artifacts/integration-certification'),
  only,
} = {}) {
  if (!['all', 'js', 'sandbox'].includes(layer))
    throw new Error('layer must be all, js or sandbox');
  mkdirSync(output, { recursive: true });
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    layer,
    live: {
      status: 'not-run',
      reason: 'Offline certification never authorizes or runs provider writes',
    },
    integrations: [],
  };
  writeFileSync(
    resolve(output, 'report.json'),
    JSON.stringify({ ...report, status: 'running' }, null, 2) + '\n',
  );
  let packages;
  try {
    packages = discover();
    if (only && !packages.some(p => p.id === only))
      throw new Error(`Unknown integration: ${only}`);
  } catch (e) {
    writeFileSync(
      resolve(output, 'report.json'),
      JSON.stringify(
        { ...report, status: 'failed', error: e.message },
        null,
        2,
      ) + '\n',
    );
    throw e;
  }
  // A normal certification run must never inherit opt-in live-test switches.
  const env = { ...process.env, ATOMICSERVER_SKIP_JS_BUILD: 'true' };
  for (const key of Object.keys(env))
    if (/^ATOMIC_(LIVE_|GITHUB_TEST_SERVER|NOTION_TEST_SERVER)/.test(key))
      delete env[key];
  const run = (command, args, log) => {
    const r = spawnSync(command, args, {
      cwd: root,
      env,
      encoding: 'utf8',
      timeout: 600000,
      maxBuffer: 32 * 1024 * 1024,
    });
    const text = `${r.stdout ?? ''}${r.stderr ?? ''}${r.error ? '\n' + r.error.message : ''}\nexit=${r.status} signal=${r.signal ?? 'none'}`;
    writeFileSync(resolve(output, log), text);
    return {
      ok: r.status === 0,
      text,
      stdout: r.stdout,
      stderr: r.stderr,
      error: r.error?.message,
    };
  };
  for (const p of packages.filter(p => !only || p.id === only)) {
    const shipped = readFileSync(resolve(root, p.path, 'plugin.js'));
    const item = {
      id: p.id,
      version: p.version,
      owner: p.owner,
      support: p.support,
      apiVersion: p.apiVersion,
      declaredCapabilities: p.capabilities,
      bundleSha256: createHash('sha256').update(shipped).digest('hex'),
      checks: [],
      status: 'pending',
    };
    report.integrations.push(item);
    const check = (name, r, extra = true, failedValidation) => {
      const passed = r.ok && extra;
      item.checks.push({
        name,
        status: passed ? 'passed' : 'failed',
        ...(passed
          ? {}
          : {
              detail: r.ok
                ? failedValidation || 'validation failed'
                : summarizeFailure(r),
            }),
      });
    };
    if (layer !== 'sandbox') {
      const bundle = run(
        resolve(root, 'browser/node_modules/.bin/esbuild'),
        [
          `${p.path}/plugin.ts`,
          '--bundle',
          '--format=esm',
          '--platform=neutral',
          '--target=es2022',
        ],
        `${p.id}-bundle.log`,
      );
      check(
        'reproducible-bundle',
        bundle,
        bundle.stdout === shipped.toString(),
        'generated bundle differs from committed plugin.js',
      );
      check(
        'typecheck',
        run(
          resolve(root, 'browser/node_modules/.bin/tsc'),
          ['-p', `${p.path}/tsconfig.json`],
          `${p.id}-types.log`,
        ),
      );
      const resultPath = resolve(output, `${p.id}-vitest.json`);
      // A unique output directory per run is recommended; stale files cannot satisfy a failed command.
      const tests = run(
        resolve(root, 'browser/node_modules/.bin/vitest'),
        [
          'run',
          '--config',
          `${p.path}/vitest.config.ts`,
          '--reporter=json',
          `--outputFile=${resultPath}`,
        ],
        `${p.id}-tests.log`,
      );
      let counts = {};
      try {
        counts = JSON.parse(readFileSync(resultPath, 'utf8'));
      } catch {}
      check(
        'fixtures',
        tests,
        evaluateJs(counts),
        'test report did not contain a successful executed test',
      );
      item.fixtureCounts = {
        passed: counts.numPassedTests ?? 0,
        skipped: counts.numPendingTests ?? 0,
        failed: counts.numFailedTests ?? 0,
      };
    }
    if (layer !== 'js')
      for (const test of p.sandboxTests) {
        const r = run(
          'cargo',
          [
            'test',
            '-p',
            'atomic-server',
            '--lib',
            test,
            '--no-default-features',
            '--features',
            'light,wasm-plugins',
            '--',
            '--exact',
          ],
          `${p.id}-${test.split('::').at(-1)}.log`,
        );
        check(
          test,
          r,
          evaluateRust(r.text),
          'sandbox output did not report exactly one passing test',
        );
      }
    item.status = item.checks.every(c => c.status === 'passed')
      ? 'passed'
      : 'failed';
    writeFileSync(
      resolve(output, 'report.json'),
      JSON.stringify({ ...report, status: 'running' }, null, 2) + '\n',
    );
    const failures = formatFailureSummary(item.checks);
    console.log(
      `${p.id}: ${item.status} (${layer}; live not run)${failures ? ` — ${failures}` : ''}`,
    );
  }
  report.status =
    report.integrations.length &&
    report.integrations.every(i => i.status === 'passed')
      ? 'passed'
      : 'failed';
  writeFileSync(
    resolve(output, 'report.json'),
    JSON.stringify(report, null, 2) + '\n',
  );
  return report;
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const args = process.argv.slice(2),
      options = {};
    for (let i = 0; i < args.length; i += 2) {
      const key = {
        '--layer': 'layer',
        '--output': 'output',
        '--integration': 'only',
      }[args[i]];
      if (!key || !args[i + 1])
        throw new Error(
          'Usage: certify.mjs [--layer all|js|sandbox] [--integration id] [--output directory]',
        );
      options[key] = key === 'output' ? resolve(args[i + 1]) : args[i + 1];
    }
    process.exitCode = certify(options).status === 'passed' ? 0 : 1;
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
}
