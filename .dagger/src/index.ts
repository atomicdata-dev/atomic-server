import {
  dag,
  Container,
  Directory,
  object,
  func,
  argument,
  Secret,
  File,
  Platform,
  Service,
  CacheSharingMode,
  CacheVolume,
} from '@dagger.io/dagger';
import { overrideE2eBudget } from './e2e-budget';

/**
 * Bumps the mtime of every mounted workspace source before cargo runs.
 *
 * The `rust-*-target` cache volumes are shared between pipelines, and cargo
 * decides whether a path dependency such as `atomic_lib` is fresh by
 * comparing source mtimes against the cached artifact. Sources arrive in the
 * container with old timestamps, so once any branch with a different `lib`
 * has written the artifact, every later run keeps it and fails to compile
 * `server` with E0425 (see the `-v2` rename in #1329, and the `-v3` one).
 * Touching the sources makes them newer than anything in the cache, so the
 * workspace crates rebuild every run while registry dependencies stay cached.
 */
const TOUCH_WORKSPACE_SOURCES = [
  'sh',
  '-c',
  'find /code/server /code/lib /code/cli /code/desktop /code/wasm ' +
    '/code/plugin-examples /code/atomic-plugin /code/tools ' +
    '-type f -exec touch {} +',
];

/**
 * One stamp per module process, so every call inside one `ci()` shares it.
 * Stamping per call gave each `wasmBuild()`/`jsBuild()` caller its own graph,
 * so Dagger could not dedupe them: one run built wasm seven times, all fighting
 * over the same target volume's cargo lock.
 */
const RUN_STAMP = new Date().toISOString();

/**
 * Runs the touch above on every pipeline run. A `withExec` is a cached layer
 * keyed on its inputs, and the Rust sources are the same bytes across many
 * commits, so the touch was replayed from cache with its old mtimes. Any
 * artifact another pipeline wrote to the shared target volume in the meantime
 * was then newer than the sources, and cargo kept it: `atomic-server` failed
 * to compile against an `atomic_lib` from a different branch (2026-09-15).
 * The changing variable makes the layer unique per run without touching the
 * command itself.
 */
function touchWorkspaceSources(container: Container): Container {
  return container
    .withEnvVariable('ATOMIC_TOUCH_RUN', RUN_STAMP)
    .withExec(TOUCH_WORKSPACE_SOURCES);
}

const NODE_IMAGE = 'node:22';
// Checked against rust-toolchain.toml by scripts/check-rust-alignment.py.
const RUST_VERSION = '1.98.1';
const RUST_IMAGE = `rust:${RUST_VERSION}-bookworm`;

// Pin the tools and their published dependency locks. Unlocked linkcheck
// installation picked up jiff 0.2.36, whose packaged doc includes are broken.
const INSTALL_DOCS_TOOLS =
  'cargo install mdbook --version 0.5.4 --locked --quiet && ' +
  'cargo install mdbook-linkcheck --version 0.7.7 --locked --quiet';

// Must match `packageManager` in `browser/package.json`, exactly.
//
// Installing any *other* version means the first pnpm invocation inside a
// workspace tries to self-switch to the declared one, and pnpm 10 cannot
// switch to pnpm 11: it downloads `@pnpm/<platform>` and then looks for the
// CLI at `.tools/@pnpm+<platform>/<version>/bin`, which pnpm 11 no longer
// ships that way. The switch dies with
//   ERROR  Failed to switch pnpm to v11.10.0. Looks like pnpm CLI is missing
// and takes every JS container with it. Upstream: pnpm/pnpm#12528.
//
// So: install the exact version, and never let the self-switch run.
const PNPM_VERSION = '11.10.0';

// Where `get.pnpm.io/install.sh` puts the CLI, for the containers that install
// pnpm that way instead of via `npm --global` (the playwright image).
//
// pnpm 10 dropped the binary straight into `$PNPM_HOME`; pnpm 11 installs
// `@pnpm/exe` and leaves shims in `$PNPM_HOME/bin` instead. Pointing PATH at
// `$PNPM_HOME` — correct until the version bump above — now yields
//   exec: "pnpm": executable file not found in $PATH
// on the container's first `pnpm install`. The install script's own PATH
// advice (`export PATH="$PNPM_HOME/bin:$PATH"`) is the authority here.
const PNPM_BIN_DIR = '/root/.local/share/pnpm/bin';

// Must match `@playwright/test` in `browser/e2e/package.json`.
//
// The image bakes in the browser builds its own Playwright wants, and each
// release wants different revisions (1.58.2 → chromium-1208, 1.60.0 →
// chromium-1223). Drift here does not fail loudly: `playwright install`
// quietly re-downloads chromium, firefox AND webkit — measured at 30s in the
// image, ~52s on Mancave, against 0s when the versions agree.
//
// That cost lands whenever the install layer is invalidated, which is any
// change under `browser/` outside `e2e/tests` (the tests mount AFTER it, so
// test-only commits stay cached). A cache volume cannot rescue it either: the
// image sets `PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`, so the download lands
// there rather than in `~/.cache`.
const PLAYWRIGHT_PACKAGE_VERSION = '1.63.0';
const PLAYWRIGHT_VERSION = `v${PLAYWRIGHT_PACKAGE_VERSION}-noble`;
// Keep in sync with `flutter/.mise.toml` (`[tools].flutter`).
const FLUTTER_IMAGE = 'ghcr.io/cirruslabs/flutter:3.44.0';
// See https://github.com/rust-cross/rust-musl-cross?tab=readme-ov-file#prebuilt-images
const TARGET_IMAGE_MAP = {
  'x86_64-unknown-linux-musl': 'ghcr.io/rust-cross/rust-musl-cross:x86_64-musl',
  'aarch64-unknown-linux-musl':
    'ghcr.io/rust-cross/rust-musl-cross:aarch64-musl',
  'armv7-unknown-linux-musleabihf':
    'ghcr.io/rust-cross/rust-musl-cross:armv7-musleabihf',
} as const;

// Service-binding alias the playwright container uses to reach
// atomic-server. Chromium hardcodes `*.localhost` to 127.0.0.1 (bypassing
// dagger's DNS injection) so we can't use a `.localhost` hostname here.
// The non-localhost hostname means the browser would NOT consider the
// origin a "secure context" by default — which is fatal because the SPA
// uses `crypto.subtle` to initialize its WASM ClientDb. We pass
// `--unsafely-treat-insecure-origin-as-secure=http://atomic:9883` to
// chromium below so the test browser exposes the secure-context APIs.
const ATOMIC_DOMAIN = 'atomic';

// CI host profiles. Main.yml passes `--host-profile mancave` only on the
// self-hosted job; the GitHub-hosted fallback keeps the conservative
// `hosted` defaults (2 vCPU). `.config/nextest.toml` still caps `it` at 2
// and serializes `iroh_pairing::*`.
//
// `cargoBuildJobs` is the important one on Mancave: dagger containers see
// all host CPUs (24 threads on the current box), so bare `cargo build` /
// `clippy` / `wasm-pack` default to -j24 and burn ~30% of wall time in
// system/context-switch. `nextest --build-jobs` only covers the nextest
// invocation — pin `CARGO_BUILD_JOBS` on every cargo container too.
type HostProfile = 'mancave' | 'hosted';

/** Playwright gate. `light` is `--grep @smoke`; `full` is the unfiltered suite.
 *  Default is `full` so a forgotten flag cannot silently shrink develop/tag CI. */
type E2eMode = 'light' | 'full';

type HostKnobs = {
  e2eShardCount: number;
  e2ePlaywrightWorkers: string;
  e2ePlaywrightRetries: string;
  nextestTestThreads: string;
  nextestRetries: string;
  nextestBuildJobs: string;
  /** Caps rustc parallelism inside each container via CARGO_BUILD_JOBS. */
  cargoBuildJobs: string;
};

type E2eRunKnobs = {
  shardCount: number;
  workers: string;
  retries: string;
  /** Empty string = unfiltered. Otherwise passed as `--grep`. */
  grep: string;
};

function resolveE2eMode(value: string): E2eMode {
  return value === 'light' ? 'light' : 'full';
}

function e2eRunKnobs(profile: HostProfile, mode: E2eMode): E2eRunKnobs {
  const host = HOST_PROFILES[profile];
  if (mode === 'light') {
    return {
      // ~17 @smoke tests: two Mancave shards is plenty; hosted keeps one
      // atomic-server. Do not mutate HostKnobs — rustTest reads those in
      // parallel with endToEnd.
      shardCount: profile === 'mancave' ? 2 : 1,
      workers: host.e2ePlaywrightWorkers,
      retries: '1',
      grep: '@smoke',
    };
  }

  return {
    shardCount: host.e2eShardCount,
    workers: host.e2ePlaywrightWorkers,
    retries: host.e2ePlaywrightRetries,
    grep: '',
  };
}

/**
 * Prints where a shard's time went: seconds per spec file and per shard, in the
 * last lines of the shard's log. The shards are contiguous slices of the test
 * list, cut by test count, so a heavy file sits in whichever slice it lands in.
 * With these numbers `PWTEST_SHARD_WEIGHTS` can be set from measurements
 * instead of guessed. Never fails the shard: a missing report prints nothing.
 */
const E2E_TIMING_SUMMARY = [
  "const fs = require('fs');",
  'let report;',
  "try { report = JSON.parse(fs.readFileSync('/test-results.json', 'utf8')); } catch { process.exit(0); }",
  'const files = new Map();',
  'let tests = 0;',
  'const walk = suite => {',
  '  for (const spec of suite.specs || []) for (const test of spec.tests) {',
  '    tests++;',
  '    const ms = test.results.reduce((sum, result) => sum + result.duration, 0);',
  '    files.set(spec.file, (files.get(spec.file) || [0, 0]).map((v, i) => v + (i ? 1 : ms)));',
  '  }',
  '  for (const child of suite.suites || []) walk(child);',
  '};',
  'for (const suite of report.suites) walk(suite);',
  'let total = 0;',
  'for (const [, [ms]] of files) total += ms;',
  "console.log('E2E-TIMING shard=' + process.argv[1] + ' tests=' + tests + ' test-seconds=' + Math.round(total / 1000));",
  'for (const [file, [ms, count]] of [...files].sort((a, b) => b[1][0] - a[1][0]))',
  "  console.log('E2E-TIMING shard=' + process.argv[1] + ' ' + String(Math.round(ms / 1000)).padStart(5) + 's ' + String(count).padStart(3) + ' tests ' + file);",
].join(' ');

/**
 * Shard sizes, in tests, for `PWTEST_SHARD_WEIGHTS`, keyed by shard count.
 *
 * Playwright cuts the test list into contiguous slices of equal test count, but
 * the tests differ in cost: with equal counts, run 4783 (one worker per shard)
 * took 30.3, ~22.9, 27.1 and 26.5 min, and a shard's minutes are its
 * `E2E-TIMING test-seconds`. These sizes come from the per-file timings of all
 * four shards on run 4790: costed per test in suite order, they put every
 * shard within 2252 to 2279 s of that run. Weights are proportions, so a
 * growing suite keeps the same split. Re-measure from the `E2E-TIMING` lines
 * when it drifts. Playwright wants the weights separated by ":" and one per
 * shard, so only a shard count with an entry here is weighted.
 */
const E2E_SHARD_WEIGHTS: Record<number, string> = {
  4: '62:90:84:79',
};

/**
 * `bash -c` payload for one Playwright shard.
 *
 * The log label must be safe inside a double-quoted `echo`. The previous
 * `JSON.stringify(grep || '(full)')` wrote `grep="(full)"`, which closed
 * the quote so bash treated `(full)` as a subshell and the shard never
 * started. Light CI hid it because `@smoke` is not a metacharacter.
 */
function e2eShardRunScript(
  grep: string,
  shardIndex: number,
  shardCount: number,
): string {
  const grepFlag = grep ? ` --grep ${JSON.stringify(grep)}` : '';
  const grepLabel = grep || 'full';

  return (
    'set -o pipefail; ' +
    `echo "e2e mode grep=${grepLabel} shard=${shardIndex}/${shardCount} workers=$PLAYWRIGHT_WORKERS retries=$PLAYWRIGHT_RETRIES"; ` +
    (E2E_SHARD_WEIGHTS[shardCount]
      ? `export PWTEST_SHARD_WEIGHTS=${E2E_SHARD_WEIGHTS[shardCount]}; `
      : '') +
    'export PLAYWRIGHT_JSON_OUTPUT_NAME=/test-results.json; ' +
    `pnpm exec playwright test --config=./playwright.config.ts${grepFlag} --shard=${shardIndex}/${shardCount} 2>&1 | tee /test-output.log; ` +
    'echo ${PIPESTATUS[0]} > /test-exit-code; ' +
    `node -e ${JSON.stringify(E2E_TIMING_SUMMARY)} ${shardIndex}/${shardCount} 2>&1 | tee -a /test-output.log; ` +
    'exit 0'
  );
}

/**
 * Trim a Playwright `error-context.md` to the part worth reading in a CI log.
 *
 * The file leads with ~2.5k characters of breadcrumbs, sidebar and app menu —
 * identical on every failure — and only then reaches the `main` region where
 * the grid, board or form under test lives. A flat head-truncation therefore
 * spends its whole budget on boilerplate and cuts off exactly the part that
 * explains the failure.
 */
function condenseErrorContext(body: string): string {
  const details = body.match(/# Error details\s*```\n([\s\S]{0,900}?)```/);
  const main = body.indexOf('- main:');
  const region =
    main === -1 ? body.slice(-2500) : body.slice(main, main + 2500);

  return `${details ? details[1].trim() : ''}\n\n${region}`;
}

const HOST_PROFILES: Record<HostProfile, HostKnobs> = {
  // Four browser workers total, one per shard/server. At eight, full develop
  // runs repeatedly exhausted settings-save and app-creation waits while the
  // same journeys passed in focused runs. The full local suite also passed
  // with two workers and no retries. Keep browser headroom alongside the
  // Rust, WASM and frontend jobs instead of widening every interaction wait.
  mancave: {
    e2eShardCount: 4,
    e2ePlaywrightWorkers: '1',
    // Back to the suite's own documented default (playwright.config.ts): three
    // attempts catch a genuinely flaky path while a real regression still
    // fails all three. This branch dropped it to 1 for runtime, and that trade
    // stopped paying: what remains red here rotates run to run — a click that
    // did not land, a menu that did not open — which is the shape of a
    // contended host, not of a broken test. Mitigation, not a fix; the fix is
    // headroom, and `ci()` still runs these browsers alongside clippy,
    // nextest, flutter and two vitest suites.
    e2ePlaywrightRetries: '2',
    // Measured 2026-09-15 on a 15-minute smoke run (24 threads, 31 GiB): the
    // engine sat at 14 to 20 cores while compiling, but only 7 to 13 cores for
    // the 7.5-minute nextest phase and the e2e phase (idle 45 to 70%). Memory
    // peaked at 8 GiB. The test widths below are where the headroom was.
    nextestTestThreads: '12',
    nextestRetries: '1',
    nextestBuildJobs: '8',
    cargoBuildJobs: '12',
  },
  // Sized for GitHub's standard hosted runner. The widths below said 2 for
  // every knob, which matched the 2-vCPU runner this profile was written
  // against; public repositories have had 4 vCPU / 16GB since 2024, so half
  // the box sat idle through every compile.
  //
  // Only the *build* widths move. Rust compilation is the dominant cost here
  // and scales cleanly with cores. The test widths stay where they are on
  // purpose: `ci()` runs endToEnd concurrently with clippy, nextest, flutter
  // and vitest, so raising those would stack more browsers and more test
  // threads onto the same four cores — the starvation the mancave notes
  // above describe. Build jobs mostly occupy phases the tests are not in.
  //
  // This profile is not the fallback it reads as: `CI_RUNNER` has been set to
  // `["ubuntu-latest"]` since 2026-09-08, and `pick` treats that as an
  // explicit escape hatch, so *every* run currently lands here.
  hosted: {
    e2eShardCount: 2,
    e2ePlaywrightWorkers: '1',
    e2ePlaywrightRetries: '2',
    nextestTestThreads: '2',
    nextestRetries: '2',
    nextestBuildJobs: '4',
    cargoBuildJobs: '4',
  },
};

function resolveHostProfile(value: string): HostProfile {
  return value === 'mancave' ? 'mancave' : 'hosted';
}

// Official `rust:*` images set `CARGO_HOME=/usr/local/cargo`. The
// rust-musl-cross images set `CARGO_HOME=/root/.cargo`. Cache mounts
// must match the image in use — a mount at the other path is a silent
// no-op and every `cargo fetch` re-downloads the world.
const CARGO_HOME_BOOKWORM = '/usr/local/cargo';
const CARGO_HOME_MUSL = '/root/.cargo';

@object()
export class AtomicServer {
  source: Directory;
  /** Active host knobs for this `ci()` invocation. Standalone func calls
   *  (rustTest/endToEnd alone) keep the conservative hosted defaults. */
  private hostKnobs: HostKnobs = HOST_PROFILES.hosted;
  private hostProfile: HostProfile = 'hosted';
  /** Playwright-only knobs for the in-flight `endToEnd` run. Isolated from
   *  `hostKnobs` so a light E2E job cannot change nextest width mid-`ci()`. */
  private e2eRun: E2eRunKnobs = e2eRunKnobs('hosted', 'full');
  private e2eCloneSessions = false;
  /** Suffix for the Rust `target/` cache volumes, one per CI runner. */
  private targetCacheSuffix = '';

  constructor(
    @argument({
      defaultPath: '.',
      ignore: [
        '**/node_modules',
        '**/.git',
        '**/.github',
        '**/.husky',
        '**/.vscode',
        // rust
        '**/target',
        '**/artifact',
        // browser
        '**/.swc',
        '**/.netlify',
        // e2e
        '**/.e2e-runs',
        '**/.e2e-store',
        '**/test-results',
        '**/template-tests',
        '**/playwright-report',
        '**/tmp',
        '**/.temp',
        '**/.cargo',
        '**/.DS_Store',
        '**/.vscode',
        '**/dist',
        '**/assets_tmp',
        '**/build',
        '**/.env',
        '**/.envrc',
        '**/bin',
      ],
    })
    source: Directory,
    /**
     * The CI runner's name. Mancave runs several runner processes on one
     * Dagger engine, and cache volumes are engine-wide, so two jobs from
     * different branches shared each `target/` volume at the same time. The
     * per-run touch cannot protect that: a build another branch finishes
     * after this run's touch is newer than this run's sources, and cargo
     * reuses it (run 4533 failed to compile `server` against another
     * branch's `atomic_lib`). One volume per runner means one job at a time
     * per volume again. Registry and pnpm caches are content-addressed and
     * stay shared. `Mancave`, the original runner, keeps the old names so its
     * warm caches survive.
     */
    @argument() cacheNamespace: string = '',
  ) {
    this.source = source;
    const namespace = cacheNamespace.trim();
    this.targetCacheSuffix =
      namespace === '' || namespace === 'Mancave'
        ? ''
        : `-${namespace.replace(/[^A-Za-z0-9_.-]/g, '-')}`;
  }

  /** A Rust `target/` cache volume, private to this CI runner. */
  private targetCache(name: string): CacheVolume {
    return dag.cacheVolume(`${name}${this.targetCacheSuffix}`);
  }

  /**
   * Mount shared crates.io + git dependency caches under `cargoHome`, and
   * pin `CARGO_BUILD_JOBS` so rustc doesn't spawn one job per visible host
   * CPU (containers see the full Mancave SMT count). Registry content is
   * identical across glibc/musl images, so both share dependency volumes
   * and Cargo cache locks — only the mount path differs.
   */
  private withCargoHomeCache(
    container: Container,
    cargoHome: string,
  ): Container {
    return (
      container
        .withExec([
          'rustup', 'toolchain', 'install', RUST_VERSION,
          '--profile', 'minimal', '--component', 'rustfmt,clippy',
        ])
        .withEnvVariable('RUSTUP_TOOLCHAIN', RUST_VERSION)
        .withMountedCache(
          `${cargoHome}/registry`,
          dag.cacheVolume('cargo-shared-locks-v1'),
          {
            sharing: CacheSharingMode.Shared,
          },
        )
        .withMountedCache(
          `${cargoHome}/git`,
          dag.cacheVolume('cargo-git-shared-locks-v1'),
          {
            sharing: CacheSharingMode.Shared,
          },
        )
        // Cargo locks live in CARGO_HOME, outside registry/git. Sharing only
        // those directories leaves every container with independent locks and
        // lets simultaneous downloads race while unpacking the same crate.
        // Put both lock inodes in the shared registry volume; Cargo still only
        // serializes downloads/mutations, not the entire parallel build lane.
        // Fresh volume names keep older jobs with private locks out of this cache.
        .withExec([
          'ln',
          '-sf',
          'registry/.package-cache',
          `${cargoHome}/.package-cache`,
        ])
        .withExec([
          'ln',
          '-sf',
          'registry/.package-cache-mutate',
          `${cargoHome}/.package-cache-mutate`,
        ])
        .withEnvVariable('CARGO_BUILD_JOBS', this.hostKnobs.cargoBuildJobs)
    );
  }

  /**
   * Cold/warm timing for the install caches this module relies on.
   * Run twice: first populates volumes, second should be near-instant
   * `cargo install` / `npm install -g` no-ops.
   */
  @func()
  async cacheBench(): Promise<string> {
    const cargoBinPath =
      '/opt/cargo-bin/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

    const [mdbookOut, netlifyOut, pubOut] = await Promise.all([
      this.withCargoHomeCache(
        dag.container().from(RUST_IMAGE),
        CARGO_HOME_BOOKWORM,
      )
        .withMountedCache('/opt/cargo-bin', dag.cacheVolume('cargo-bin'), {
          sharing: CacheSharingMode.Shared,
        })
        .withEnvVariable('CARGO_INSTALL_ROOT', '/opt/cargo-bin')
        .withEnvVariable('PATH', cargoBinPath)
        .withExec([
          'sh',
          '-c',
          'echo "=== mdbook install ===" && ' +
            'if [ -x /opt/cargo-bin/bin/mdbook ] && [ -x /opt/cargo-bin/bin/mdbook-linkcheck ]; then echo "cache_hit=1"; fi && ' +
            'START=$(date +%s) && ' +
            INSTALL_DOCS_TOOLS +
            ' && ' +
            'END=$(date +%s) && ' +
            'echo "elapsed_s=$((END-START))" && ' +
            'mdbook --version && mdbook-linkcheck --version',
        ])
        .stdout(),
      dag
        .container()
        .from(NODE_IMAGE)
        .withMountedCache('/opt/npm-global', dag.cacheVolume('npm-global'))
        .withMountedCache('/root/.npm', dag.cacheVolume('npm-cache'))
        .withEnvVariable('NPM_CONFIG_PREFIX', '/opt/npm-global')
        .withEnvVariable(
          'PATH',
          '/opt/npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        )
        .withExec([
          'sh',
          '-c',
          'echo "=== netlify-cli install ===" && ' +
            'START=$(date +%s) && ' +
            'if [ ! -x /opt/npm-global/bin/netlify ]; then npm install -g netlify-cli --quiet; else echo "cache_hit=1"; fi && ' +
            'END=$(date +%s) && ' +
            'echo "elapsed_s=$((END-START))" && ' +
            'netlify --version',
        ])
        .stdout(),
      dag
        .container()
        .from(FLUTTER_IMAGE)
        .withEnvVariable('CI', 'true')
        .withEnvVariable('PUB_CACHE', '/root/.pub-cache')
        .withMountedCache(
          '/root/.pub-cache',
          dag.cacheVolume('flutter-pub-cache'),
        )
        .withDirectory('/workspace/flutter', this.source.directory('flutter'))
        // `flutter/pubspec.yaml` points at ../packages/atomic_flutter.
        .withDirectory(
          '/workspace/packages',
          this.source.directory('packages'),
        )
        .withWorkdir('/workspace/flutter')
        .withExec([
          'bash',
          '-lc',
          'echo "=== flutter pub get ===" && ' +
            'START=$(date +%s) && ' +
            'flutter --version >/dev/null && flutter pub get && ' +
            'END=$(date +%s) && ' +
            'echo "elapsed_s=$((END-START))"',
        ])
        .stdout(),
    ]);

    return [mdbookOut, netlifyOut, pubOut].join('\n');
  }

  @func()
  async ci(
    @argument() netlifyAuthToken: Secret,
    /**
     * Publish docs to the live sites instead of preview URLs. Pass
     * `--publish-docs` only from a stable `v*` tag (the same ref production
     * deploys). Left off, every build gets a Netlify preview and the published
     * docs stay whatever the last stable tag put there.
     */
    @argument() publishDocs = false,
    /**
     * `mancave` = explicit aggregate budget for the self-hosted runner.
     * Measure the WSL allocation, not installed RAM (24 logical CPUs / 31 GiB
     * observed on 2026-09-12); see planning/e2e-concurrency.md.
     * `hosted` (default) = conservative knobs for ubuntu-latest fallback.
     * Passed from `.github/workflows/main.yml` per job.
     */
    @argument() hostProfile: string = 'hosted',
    /**
     * Playwright suite. `light` = `@smoke` first-hour journeys (feature
     * branches). `full` = every spec (`develop`, `v*` tags, opt-in).
     * Default `full` so omitting the flag cannot shrink a release gate.
     *
     * Named `playwrightMode` rather than `e2eMode`: Dagger's kebab-case
     * parser maps `--e2e-mode` to `e2EMode` (capital after a digit) and
     * then cannot find the argument.
     */
    @argument() playwrightMode: string = 'full',
    /** Per-shard worker override; 0 keeps the host profile. */
    @argument() playwrightWorkers: number = 0,
    /** Number of isolated servers; 0 keeps the host profile. */
    @argument() playwrightShards: number = 0,
    /** -1 keeps the host profile; 0 exposes failures without retrying. */
    @argument() playwrightRetries: number = -1,
    /** Reuse closed worker profiles for eligible drive-scoped specs. */
    @argument() playwrightCloneSessions: boolean = false,
    /**
     * Where failed e2e shards leave their traces, for `failedTestResults` to
     * hand back. The workflow passes `<run id>-<attempt>`; empty keeps none.
     */
    @argument() resultsKey: string = '',
  ): Promise<string> {
    this.hostProfile = resolveHostProfile(hostProfile);
    this.hostKnobs = HOST_PROFILES[this.hostProfile];
    overrideE2eBudget(
      e2eRunKnobs(this.hostProfile, resolveE2eMode(playwrightMode)),
      playwrightWorkers,
      playwrightShards,
      playwrightRetries,
    );

    // Fail fast on cheap static checks. A store.ts oxfmt miss used to burn
    // ~20+ minutes of rust/e2e compile before jsLint surfaced it.
    await Promise.all([this.jsLint(), this.jsTypecheck(), this.rustFmt()]);

    // Rust clippy/test still share the `rust-target` cache mount — keep
    // them serialized (parallel cargo contended the target lock for
    // ~16 minutes and exited 101). Everything else is independent.
    await Promise.all([
      this.docsPublish(netlifyAuthToken, publishDocs),
      this.typedocPublish(netlifyAuthToken, publishDocs),
      this.endToEnd(
        netlifyAuthToken,
        playwrightMode,
        playwrightWorkers,
        playwrightShards,
        playwrightRetries,
        '',
        playwrightCloneSessions,
        resultsKey,
      ),
      this.jsTest(),
      this.jsTestIntegration(),
      this.flutterTest(),
      (async () => {
        await this.rustClippy();
        await this.rustTest();
      })(),
    ]);

    return 'CI pipeline completed successfully';
  }

  @func()
  async jsLint(): Promise<string> {
    const depsContainer = this.jsSource();

    return depsContainer
      .withWorkdir('/app')
      .withExec(['pnpm', 'run', 'lint'])
      .stdout();
  }

  @func()
  async jsTypecheck(): Promise<string> {
    // A first attempt at this (#1590) ran `pnpm run typecheck` here, passed
    // on a checkout, and failed sixty seconds into its first CI run. Nothing
    // it reported was a type error: `jsSource()` does not lay the tree out
    // the way a checkout does. The three differences it hit are handled
    // below, each one reproduced and then re-checked against a replica of
    // this container's paths. A clean `tsc` in a checkout proves nothing
    // about this function, so validate a change to it the same way, or by
    // dispatching `main.yml` on a branch.
    const depsContainer = this.jsSource()
      // 1. `data-browser/tsconfig.json` maps `@repo-lib-defaults/*` to
      //    `../../lib/defaults/*`, which is repo-root `lib/defaults`. The
      //    browser mounts at /app, so that lands on /lib/defaults, where
      //    `jsSource()` places only `tasks.json`, and bootstrap.ts's ten
      //    imports came back TS2307. Mount the directory itself. As with the
      //    genesis vectors mounted beside it, staying a level below /lib
      //    leaves the OS libraries alone.
      .withDirectory('/lib/defaults', this.source.directory('lib/defaults'));

    return (
      depsContainer
        .withWorkdir('/app')
        // 2. Packages reached through node_modules need a `dist`. Building
        //    only lib and react left `@tomic/plugin`, `@tomic/service-ui` and
        //    `@tomic/edit-mode/react` unresolvable, and `@tomic/form-app`
        //    needs `@tomic/form-renderer`. All six build from TypeScript
        //    alone, so this stays in the cheap static tier beside lint and
        //    `cargo fmt`: no WASM, no Rust.
        .withExec([
          'pnpm',
          '--filter',
          '@tomic/form-renderer',
          '--filter',
          '@tomic/lib',
          '--filter',
          '@tomic/react',
          '--filter',
          '@tomic/plugin',
          '--filter',
          '@tomic/service-ui',
          '--filter',
          '@tomic/edit-mode',
          'build',
        ])
        .withExec([
          'pnpm',
          '--filter=!@tomic/data-browser',
          'run',
          '-r',
          '--parallel',
          'typecheck',
        ])
        // 3. data-browser is the one package that reaches repo-root
        //    `integrations`, and those files import
        //    `../../browser/lib/src/index.js`, which here is /browser: the
        //    symlink `jsSource()` makes so integration tsconfigs can find
        //    `../../browser/tsconfig.build.json`. `tsc` keeps whichever
        //    prefix it is handed, so compiling data-browser as /app while its
        //    own imports arrive as /browser produces two unrelated
        //    declarations of every type in `lib`, which is the wall of
        //    "Store is not assignable to Store" the first attempt hit.
        //    Naming the project by its /browser path puts both ends on one
        //    prefix. A workdir cannot do this: the kernel resolves the
        //    symlink, so `process.cwd()` would be /app again.
        .withExec([
          'pnpm',
          '--filter',
          '@tomic/data-browser',
          'exec',
          'tsc',
          '--noEmit',
          '-p',
          '/browser/data-browser/tsconfig.json',
        ])
        .stdout()
    );
  }

  @func()
  async jsTest(): Promise<string> {
    const depsContainer = this.jsBuild();

    return (
      depsContainer
        .withWorkdir('/app')
        .withExec(['pnpm', 'run', 'test'])
        // jsBuild mounts external integration tests at /integrations and
        // exposes the installed browser workspace at /browser.
        .withExec([
          '/app/node_modules/.bin/vitest',
          'run',
          '--config',
          '/integrations/localthought/vitest.config.ts',
        ])
        .withWorkdir('/app')
        .withExec([
          'node',
          '--test',
          'data-browser/scripts/integration-mcp.test.mjs',
        ])
        .stdout()
    );
  }

  /**
   * Flutter unit/widget tests + static analysis. The FFI plugin (cargokit)
   * compiles `flutter/rust` against repo-root `lib/` (`atomic_lib`);
   * both trees are mounted under `/workspace/`.
   */
  @func()
  async flutterTest(): Promise<string> {
    // Dedicated registry volume — do NOT share the main `cargo` volume used
    // by the rust/wasm lanes. A Locked mount here used to serialize pub get /
    // analyze / dart test behind the rust pipeline (~10+ min of lock wait on
    // the step that merely ran `flutter pub get`).
    // The volume is still mounted Shared, so its Cargo locks live inside it
    // (see the symlinks below). A fresh name keeps older branches, which
    // mount it with private locks, out of this cache.
    const flutterCargoCache = dag.cacheVolume('flutter-cargo-shared-locks-v1');
    const flutterRustTarget = this.targetCache('flutter-plugin-rust-target');
    const flutterPubCache = dag.cacheVolume('flutter-pub-cache');
    const flutterRustup = dag.cacheVolume('flutter-rustup');
    const pathPrefix = 'export PATH="$HOME/.cargo/bin:$PATH"';

    return (
      dag
        .container()
        .from(FLUTTER_IMAGE)
        .withEnvVariable('RUSTUP_TOOLCHAIN', RUST_VERSION)
        .withEnvVariable('CI', 'true')
        // Same pin as withCargoHomeCache — flutter's cargokit build would
        // otherwise see all host CPUs.
        .withEnvVariable('CARGO_BUILD_JOBS', this.hostKnobs.cargoBuildJobs)
        // Persist hosted Dart packages across CI runs.
        .withEnvVariable('PUB_CACHE', '/root/.pub-cache')
        .withMountedCache('/root/.pub-cache', flutterPubCache)
        // Persist the rustup toolchain so a layer-cache miss doesn't
        // re-download rustc. Idempotent install below.
        .withMountedCache('/root/.rustup', flutterRustup)
        .withExec(['apt-get', 'update', '-qq'])
        .withExec([
          'apt-get',
          'install',
          '-y',
          '--no-install-recommends',
          'ca-certificates',
          'curl',
          'git',
          'build-essential',
          'cmake',
          'ninja-build',
          'pkg-config',
          'libssl-dev',
          'clang',
        ])
        .withExec([
          'sh',
          '-c',
          'if [ ! -x "$HOME/.cargo/bin/rustc" ]; then curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; fi',
        ])
        .withExec([
          'sh', '-c',
          `${pathPrefix}; rustup toolchain install ${RUST_VERSION} --profile minimal`,
        ])
        .withDirectory('/workspace/lib', this.source.directory('lib'))
        .withDirectory('/workspace/flutter', this.source.directory('flutter'))
        // `flutter/pubspec.yaml` points at ../packages/atomic_flutter.
        .withDirectory(
          '/workspace/packages',
          this.source.directory('packages'),
        )
        .withMountedCache('/workspace/flutter/rust/target', flutterRustTarget, {
          sharing: CacheSharingMode.Locked,
        })
        .withWorkdir('/workspace/flutter')
        .withExec([
          'bash',
          '-lc',
          `${pathPrefix} && flutter --version && flutter pub get`,
        ])
        // Scope like `Makefile analyze`: cargokit `build_tool` is a nested
        // Dart package — analyzing the whole repo without its own pub get fails.
        .withExec(['bash', '-lc', `${pathPrefix} && flutter analyze lib test`])
        .withExec(['bash', '-lc', `${pathPrefix} && flutter test --no-pub`])
        // Mount cargo registry only for the Rust step so Dart work above
        // never contends for a cache volume.
        .withMountedCache('/root/.cargo/registry', flutterCargoCache, {
          sharing: CacheSharingMode.Shared,
        })
        // Same reason as withCargoHomeCache: Cargo's package-cache locks sit
        // in CARGO_HOME, outside the shared volume, so two runs on one engine
        // unpacked the same crate at once and failed with
        // "failed to unpack package ... .cargo-ok: File exists".
        .withExec([
          'ln',
          '-sf',
          'registry/.package-cache',
          '/root/.cargo/.package-cache',
        ])
        .withExec([
          'ln',
          '-sf',
          'registry/.package-cache-mutate',
          '/root/.cargo/.package-cache-mutate',
        ])
        // The flutter_rust_bridge crate is workspace-excluded (root Cargo.toml
        // `exclude`), so `rustTest`'s `--workspace` run never compiles it and
        // `flutter test` only runs Dart. Without this step the entire bridge —
        // including the canvas editing-session cache, where a stale session
        // duplicates or reverts a peer's stroke — ships untested.
        .withExec([
          'bash',
          '-lc',
          `${pathPrefix} && ` +
            'if [ ! -x "$HOME/.cargo/bin/rustc" ]; then curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; fi && ' +
            'cargo test --manifest-path rust/Cargo.toml',
        ])
        .stdout()
    );
  }

  /** Builds the WASM bundle (wasm-pack) used by `NodeClientDb` in the
   *  `@tomic/lib` integration tests. Returns a Directory containing the
   *  emitted `pkg/` artifacts. */
  @func()
  wasmBuild(): Directory {
    return (
      this.withCargoHomeCache(
        dag.container().from(RUST_IMAGE),
        CARGO_HOME_BOOKWORM,
      )
        // Use the pinned upstream executable instead of compiling wasm-pack
        // on every cold runner. Install before source inputs so Rust edits
        // cannot invalidate this layer; no mutable volume hides the binary.
        .withFile(
          '/tmp/install-wasm-pack.sh',
          this.source.file('.dagger/scripts/install-wasm-pack.sh'),
        )
        .withExec(['sh', '/tmp/install-wasm-pack.sh'])
        .withoutFile('/tmp/install-wasm-pack.sh')
        .withFile('/code/Cargo.toml', this.source.file('Cargo.toml'))
        .withFile('/code/Cargo.lock', this.source.file('Cargo.lock'))
        // wasm-pack runs `cargo metadata` which validates every workspace
        // member, so all members must be present even though we only build
        // the wasm crate.
        .withDirectory('/code/lib', this.source.directory('lib'))
        .withDirectory(
          '/code/plugin-runtime',
          this.source.directory('plugin-runtime'),
        )
        .withDirectory('/code/wasm', this.source.directory('wasm'))
        .withDirectory('/code/server', this.source.directory('server'))
        .withDirectory('/code/cli', this.source.directory('cli'))
        .withDirectory('/code/desktop', this.source.directory('desktop'))
        .withDirectory(
          '/code/plugin-examples',
          this.source.directory('plugin-examples'),
        )
        .withDirectory(
          '/code/atomic-plugin',
          this.source.directory('atomic-plugin'),
        )
        .withDirectory('/code/tools', this.source.directory('tools'))
        .withMountedCache(
          '/code/target',
          this.targetCache('rust-wasm-target-v3'),
        )
        .with(touchWorkspaceSources)
        .withWorkdir('/code/wasm')
        // The encoded-rustflags separator applies only to the WASM build.
        .withExec([
          'sh',
          '-c',
          'CARGO_ENCODED_RUSTFLAGS=\'--cfg\x1fgetrandom_backend="wasm_js"\' ' +
            'wasm-pack build --target web --out-dir pkg',
        ])
        .directory('/code/wasm/pkg')
    );
  }

  /** Builds the `atomic-server` binary without depending on a built
   *  data-browser bundle. `ATOMICSERVER_SKIP_JS_BUILD=true` short-circuits
   *  `server/build.rs`'s JS bundling step. Sufficient for headless API
   *  tests that don't render the front-end. */
  @func()
  rustBuildSlim(): File {
    return (
      this.withCargoHomeCache(
        dag
          .container()
          .from(RUST_IMAGE)
          // `protobuf-compiler` gives `protoc`, needed by `lance-encoding`'s
          // build script (transitive dep via the default `vector-search`
          // feature, which this container builds with — unlike `rustBuild`'s
          // musl targets, this glibc container doesn't need `--features
          // light`, since `ort`'s missing-prebuilt-binary gap is musl-cuda
          // specific). Matches the apt list already on `rustBuild()` /
          // `rustChecksContainer()` — this container just never had it.
          .withExec(['apt-get', 'update', '-qq'])
          .withExec(['apt', 'install', '-y', 'protobuf-compiler']),
        CARGO_HOME_BOOKWORM,
      )
        .withFile('/code/Cargo.toml', this.source.file('Cargo.toml'))
        .withFile('/code/Cargo.lock', this.source.file('Cargo.lock'))
        .withDirectory('/code/server', this.source.directory('server'))
        .withDirectory('/code/lib', this.source.directory('lib'))
        .withDirectory(
          '/code/plugin-runtime',
          this.source.directory('plugin-runtime'),
        )
        .withDirectory('/code/cli', this.source.directory('cli'))
        .withDirectory('/code/desktop', this.source.directory('desktop'))
        .withDirectory('/code/wasm', this.source.directory('wasm'))
        .withDirectory(
          '/code/plugin-examples',
          this.source.directory('plugin-examples'),
        )
        .withDirectory(
          '/code/atomic-plugin',
          this.source.directory('atomic-plugin'),
        )
        .withDirectory('/code/tools', this.source.directory('tools'))
        // `server/src/forms.rs` pins its validation verdicts to the cases the
        // browser form renderer shares (`include_str!`), so the Rust tests need
        // this one file from `browser/`.
        .withFile(
          '/code/browser/form-renderer/shared/validation-cases.json',
          this.source.file('browser/form-renderer/shared/validation-cases.json'),
        )
        .withMountedCache('/code/target', this.targetCache('rust-slim-target-v3'))
        .with(touchWorkspaceSources)
        .withWorkdir('/code')
        .withEnvVariable('ATOMICSERVER_SKIP_JS_BUILD', 'true')
        // build.rs still wants to bundle the data-browser dist as embedded
        // static files. Skipping the JS build is fine — but we still need
        // *some* directory to satisfy `static_files::resource_dir`. Drop a
        // placeholder index.html so the macro has something to embed.
        .withExec(['mkdir', '-p', '/code/server/assets_tmp'])
        .withExec([
          'sh',
          '-c',
          'echo "<html><body>integration test stub</body></html>" > /code/server/assets_tmp/index.html',
        ])
        // `--no-default-features --features light`: default features pull
        // in `vector-search` -> `ort`, and the prebuilt ONNX Runtime binary
        // `ort` downloads here expects a newer glibc ABI than `rust:bookworm`
        // ships (`undefined reference to __isoc23_strtoll` and friends —
        // ISO C23 libc symbols this base image's glibc predates). Same
        // underlying ort/onnxruntime binary-compatibility fragility as the
        // musl-cuda gap in `rustBuild`/`rustChecksContainer`, different
        // symptom. `jsTestIntegration` (this container's only caller) tests
        // `@tomic/lib`'s NodeClientDb sync path — it never touches
        // vector-search, so dropping it here costs no real coverage.
        .withExec([
          'cargo',
          'build',
          '--locked',
          '-p',
          'atomic-server',
          '--no-default-features',
          '--features',
          'light,wasm-plugins',
        ])
        .withExec([
          'cp',
          '/code/target/debug/atomic-server',
          '/atomic-server-binary',
        ])
        .file('/atomic-server-binary')
    );
  }

  /** Runs the `@tomic/lib` integration tests, which spawn a real
   *  `atomic-server` and use `NodeClientDb`. Both artefacts (binary + WASM)
   *  come from the Rust workspace and are mounted at the paths the fixture
   *  (`browser/lib/tests/server-fixture.ts`) resolves relative to the repo
   *  root.
   *
   *  Builds a minimal JS environment from scratch instead of reusing
   *  `jsBuild()` — the full workspace build runs data-browser's `build:wasm`
   *  step which expects the wasm source mounted, while these tests only
   *  need `@tomic/lib`'s source + node_modules. */
  @func()
  async jsTestIntegration(): Promise<string> {
    const binary = this.rustBuildSlim();
    const wasmPkg = this.wasmBuild();

    const browser = this.source.directory('browser');
    const pnpmContainer = dag
      .container()
      .from(NODE_IMAGE)
      // Straight to the declared version — see PNPM_VERSION. Going through
      // corepack with a 10.x line meant pnpm had to self-switch to 11 on
      // first use, which is broken.
      .withExec(['npm', 'install', '--global', `pnpm@${PNPM_VERSION}`])
      // Hoisting must be a *persistent* setting, not a CLI flag. pnpm 11
      // (see browser/package.json `packageManager`) runs a deps-status check
      // before every `pnpm run`, and re-invokes `pnpm install` itself when
      // node_modules looks stale. That implicit install doesn't inherit
      // `--shamefully-hoist`, so it sees a changed hoisting config, decides
      // node_modules must be purged, and — with no TTY to confirm — aborts
      // with ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY. `PNPM_CONFIG_*` is
      // read by every pnpm invocation in the container, implicit ones
      // included, so the two agree and no purge is ever proposed.
      //
      // Deliberately an env var rather than `shamefullyHoist: true` in
      // pnpm-workspace.yaml: that file is shared with developers, and
      // flattening node_modules locally would hide undeclared dependencies
      // that currently fail fast.
      .withEnvVariable('PNPM_CONFIG_SHAMEFULLY_HOIST', 'true')
      .withWorkdir('/repo/browser');

    // Mount workspace package manifests for caching and `pnpm install`.
    const installed = pnpmContainer
      .withFile('/repo/browser/package.json', browser.file('package.json'))
      .withFile('/repo/browser/pnpm-lock.yaml', browser.file('pnpm-lock.yaml'))
      .withDirectory('/repo/browser/patches', browser.directory('patches'))
      .withFile(
        '/repo/browser/pnpm-workspace.yaml',
        browser.file('pnpm-workspace.yaml'),
      )
      .withFile(
        '/repo/browser/data-browser/package.json',
        browser.file('data-browser/package.json'),
      )
      .withFile(
        '/repo/browser/lib/package.json',
        browser.file('lib/package.json'),
      )
      .withFile(
        '/repo/browser/react/package.json',
        browser.file('react/package.json'),
      )
      .withFile(
        '/repo/browser/svelte/package.json',
        browser.file('svelte/package.json'),
      )
      .withFile(
        '/repo/browser/cli/package.json',
        browser.file('cli/package.json'),
      )
      .withFile(
        '/repo/browser/create-template/package.json',
        browser.file('create-template/package.json'),
      )
      .withFile(
        '/repo/browser/plugin/package.json',
        browser.file('plugin/package.json'),
      )
      .withFile(
        '/repo/browser/mcp/package.json',
        browser.file('mcp/package.json'),
      )
      .withFile(
        '/repo/browser/e2e/package.json',
        browser.file('e2e/package.json'),
      )
      // The lib's tsconfig.json extends the workspace-level tsconfigs.
      .withFile('/repo/browser/tsconfig.json', browser.file('tsconfig.json'))
      .withFile(
        '/repo/browser/tsconfig.build.json',
        browser.file('tsconfig.build.json'),
      )
      // Same pnpm-store volume as jsBuild() — without this, every
      // integration-test run re-downloaded the registry graph.
      .withMountedCache(
        '/repo/browser/.pnpm-store',
        dag.cacheVolume('pnpm-store'),
      )
      .withExec([
        'pnpm',
        'config',
        'set',
        'store-dir',
        '/repo/browser/.pnpm-store',
      ])
      // Hoisting comes from PNPM_CONFIG_SHAMEFULLY_HOIST above, and the
      // `yes |` that used to answer the purge prompt is no longer needed —
      // nothing prompts once the setting is persistent.
      .withExec(['pnpm', 'install', '--frozen-lockfile']);

    // Drop in @tomic/lib source. Other packages are unused by the
    // integration tests, except @tomic/mcp: hosted-mcp.integration.test.ts
    // imports its bridge from `../../mcp/src`.
    const withSource = installed
      .withDirectory('/repo/browser/lib', browser.directory('lib'))
      .withDirectory('/repo/browser/mcp', browser.directory('mcp'));

    return withSource
      .withFile('/repo/target/debug/atomic-server', binary, {
        permissions: 0o755,
      })
      .withDirectory('/repo/wasm/pkg', wasmPkg)
      .withWorkdir('/repo/browser/lib')
      .withExec(['pnpm', 'run', 'test:integration'])
      .stdout();
  }

  @func()
  docsPublish(
    @argument() netlifyAuthToken: Secret,
    /** Publish to the live docs site rather than a preview URL. */
    @argument() prod = false,
  ): Promise<string> {
    const builtDocsHtml = this.docsFolder();

    return this.netlifyDeploy(
      builtDocsHtml,
      'atomic-docs',
      netlifyAuthToken,
      prod,
    );
  }

  private netlifyDeploy(
    /** The directory to deploy */
    directory: Directory,
    siteName: string,
    netlifyAuthToken: Secret,
    /**
     * Publish to the live site rather than a preview URL. Off by default: this
     * runs inside `ci()`, which runs on every push to every branch, so a
     * `--prod` default meant any feature branch republished the public docs.
     * Only the workflow knows the branch, so only the workflow may ask for it.
     */
    prod = false,
  ): Promise<string> {
    const target = prod ? '--prod' : '';

    return this.netlifyCliContainer()
      .withDirectory('/deploy', directory)
      .withWorkdir('/deploy')
      .withSecretVariable('NETLIFY_AUTH_TOKEN', netlifyAuthToken)
      .withExec([
        'sh',
        '-c',
        // Skip silently when no auth token is configured (PR builds from
        // forks, branches without secret access). Netlify CLI 23+ rejects
        // empty `--auth ""` instead of treating it as missing.
        `if [ -z "$NETLIFY_AUTH_TOKEN" ]; then echo 'NETLIFY_AUTH_TOKEN not set — skipping ${siteName} deploy'; exit 0; fi; for i in $(seq 1 5); do netlify link --name ${siteName} --auth "$NETLIFY_AUTH_TOKEN" && break || sleep 2; done && netlify deploy --dir . ${target} --auth "$NETLIFY_AUTH_TOKEN"`,
      ])
      .stdout();
  }

  /**
   * Node image with a cached global `netlify-cli`. Routed through
   * `NPM_CONFIG_PREFIX=/opt/npm-global` so the cache mount can't hide
   * the image's preinstalled npm/node. `npm install -g` no-ops when the
   * package is already present at that prefix.
   */
  private netlifyCliContainer(): Container {
    return (
      dag
        .container()
        .from(NODE_IMAGE)
        .withMountedCache('/opt/npm-global', dag.cacheVolume('npm-global'))
        .withMountedCache('/root/.npm', dag.cacheVolume('npm-cache'))
        .withEnvVariable('NPM_CONFIG_PREFIX', '/opt/npm-global')
        .withEnvVariable(
          'PATH',
          '/opt/npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        )
        // Install + version check in one exec so a cleared volume can't
        // leave `netlify` missing on a dagger layer-cache hit. Unlike
        // `cargo install`, `npm install -g` is NOT a no-op when the
        // package is already present — it still walks the tree (~15-60s) —
        // so skip when the binary exists.
        .withExec([
          'sh',
          '-c',
          'if [ ! -x /opt/npm-global/bin/netlify ]; then npm install -g netlify-cli --quiet; fi && netlify --version',
        ])
    );
  }

  /**
   * Extracts the unique deploy URL from netlify output.
   *
   * Says which of the two failures happened, because they need opposite
   * responses and for weeks they printed the same sentence. `netlifyDeploy`
   * exits 0 with a skip message when `NETLIFY_AUTH_TOKEN` is empty, so an
   * unset secret and a parse miss both arrived as "Deploy URL not found" —
   * which reads like the URL format changed and is the reason nobody noticed
   * that every failed e2e run on develop was publishing no report at all.
   *
   * That report is not a nicety. `playwright.config.ts` records traces with
   * `retain-on-failure`, and this deploy is the only path that carries them
   * off the runner: Dagger keeps the traces in its container, which is
   * discarded when the `ci` call throws. So with the token unset the
   * per-shard 20k-char log tail is the entire evidence channel for a failed
   * run, and "which assertion failed" arrives without "why".
   */
  private extractDeployUrl(netlifyOutput: string): string {
    const match = netlifyOutput.match(/https:\/\/[a-f0-9]+--.+\.netlify\.app/);

    if (match) return match[0];

    if (netlifyOutput.includes('NETLIFY_AUTH_TOKEN not set')) {
      return 'no report deployed — NETLIFY_AUTH_TOKEN is empty on this runner, so traces and error-context for this shard were discarded with the container';
    }

    return 'Deploy URL not found (netlify ran but printed no deploy URL)';
  }

  @func()
  docsFolder(): Directory {
    const actualDocsDirectory = this.source.directory('docs');

    return (
      this.withCargoHomeCache(
        dag.container().from(RUST_IMAGE),
        CARGO_HOME_BOOKWORM,
      )
        // Same cargo-install binary cache as wasmBuild() — without it,
        // every CI run recompiled mdbook + mdbook-linkcheck from source
        // (~4 min). Routed through `CARGO_INSTALL_ROOT` so the cache
        // mount can't hide the rust image's preinstalled `cargo`/`rustc`
        // at `/usr/local/cargo/bin`. `cargo install` no-ops when the
        // binaries are already present at the install root.
        .withMountedCache('/opt/cargo-bin', dag.cacheVolume('cargo-bin'), {
          // Shared so wasm-pack and mdbook installs can proceed in parallel.
          sharing: CacheSharingMode.Shared,
        })
        .withEnvVariable('CARGO_INSTALL_ROOT', '/opt/cargo-bin')
        .withEnvVariable(
          'PATH',
          '/opt/cargo-bin/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        )
        .withMountedDirectory('/docs', actualDocsDirectory)
        .withWorkdir('/docs')
        // Install + build in a single exec so the install is part of the
        // build step's own cache key. Splitting them lets dagger cache the
        // `cargo install` step as "already ran" while the mounted
        // `cargo-bin` cache volume can be cleared by the engine (e.g. after
        // a restart with `Locked` sharing), leaving mdbook missing from
        // PATH on replay. Bundling makes any cache hit imply the binaries
        // are present too; `cargo install` no-ops when they are current.
        .withExec(['sh', '-c', INSTALL_DOCS_TOOLS + ' && mdbook build'])
        .directory('/docs/build')
    );
  }

  @func()
  typedocPublish(
    @argument() netlifyAuthToken: Secret,
    /** Publish to the live typedoc site rather than a preview URL. */
    @argument() prod = false,
  ): Promise<string> {
    const browserDir = this.jsBuild();

    return (
      browserDir
        .withWorkdir('/app')
        .withSecretVariable('NETLIFY_AUTH_TOKEN', netlifyAuthToken)
        // The `--prod` flag lives in the pnpm script, so it is steered by env
        // rather than argv — see `typedoc-publish` in browser/package.json.
        .withEnvVariable('NETLIFY_PROD', prod ? '1' : '')
        .withExec(['pnpm', 'run', 'typedoc-publish'])
        .stdout()
    );
  }

  /** Installed workspace sources; deliberately has no build or WASM dependency. */
  private jsSource(): Container {
    const browser = this.source.directory('browser');
    // Create a container with PNPM installed
    const pnpmContainer = dag
      .container()
      .from(NODE_IMAGE)
      // Exact declared version, no corepack, no self-switch — see PNPM_VERSION.
      .withExec(['npm', 'install', '--global', `pnpm@${PNPM_VERSION}`])
      // See jsTestIntegration() for why hoisting is an env var and not a
      // `--shamefully-hoist` flag: pnpm 11's pre-run deps check re-invokes
      // `pnpm install` without the flag, reads that as a hoisting-config
      // change, and aborts trying to purge node_modules without a TTY.
      .withEnvVariable('PNPM_CONFIG_SHAMEFULLY_HOIST', 'true')
      .withWorkdir('/app');

    // Copy workspace files first for caching node_modules.
    const workspaceContainer = pnpmContainer
      .withFile('/app/package.json', browser.file('package.json'))
      .withFile('/app/pnpm-lock.yaml', browser.file('pnpm-lock.yaml'))
      .withDirectory('/app/patches', browser.directory('patches'))
      .withFile('/app/pnpm-workspace.yaml', browser.file('pnpm-workspace.yaml'))
      .withFile(
        '/app/data-browser/package.json',
        browser.file('data-browser/package.json'),
      )
      .withFile('/app/lib/package.json', browser.file('lib/package.json'))
      .withFile('/app/react/package.json', browser.file('react/package.json'))
      .withFile('/app/svelte/package.json', browser.file('svelte/package.json'))
      .withFile('/app/cli/package.json', browser.file('cli/package.json'))
      .withFile(
        '/app/create-template/package.json',
        browser.file('create-template/package.json'),
      )
      .withFile('/app/plugin/package.json', browser.file('plugin/package.json'))
      .withFile('/app/e2e/package.json', browser.file('e2e/package.json'))
      // The published-form runtime and its renderer. Without their manifests
      // here, the install gives `form-app` no node_modules and no link to
      // `@tomic/form-renderer`, so its typecheck and build cannot resolve
      // either (or `altcha`).
      .withFile(
        '/app/form-app/package.json',
        browser.file('form-app/package.json'),
      )
      .withFile(
        '/app/form-renderer/package.json',
        browser.file('form-renderer/package.json'),
      )
      // Cache pnpm's content-addressable store across CI runs. Without
      // this, every push re-downloaded all node_modules from the
      // registry — adding ~30-60s per run depending on registry latency.
      // The store is mounted at a workspace-local path and pnpm is
      // pointed at it explicitly; the default
      // `~/.local/share/pnpm/store` wouldn't be picked up by a mount at
      // `/app/.pnpm-store` without the config command.
      .withMountedCache('/app/.pnpm-store', dag.cacheVolume('pnpm-store'))
      .withExec(['pnpm', 'config', 'set', 'store-dir', '/app/.pnpm-store'])
      .withExec(['pnpm', 'install', '--frozen-lockfile']);

    // data-browser bootstrap JSON lives in repo-root lib/defaults. Vite resolves ../../../lib
    // from data-browser/src to filesystem /lib if /app is only browser — do not mount there
    // (it overwrites OS /lib). Mount alongside browser and resolve via alias in vite.config.
    const sourceContainer = workspaceContainer
      .withDirectory('/app', browser)
      // Integration sources live at the repository root. The browser mounts at
      // /app, and its raw imports resolve these paths from /integrations.
      .withDirectory('/integrations', this.source.directory('integrations'))
      // integrations/localthought/tsconfig.json extends the repo-root-relative
      // `../../browser/tsconfig.build.json`. Alias /browser to the /app mount
      // so that relative path resolves.
      .withExec(['ln', '-s', '/app', '/browser'])
      .withDirectory('/app/lib-defaults', this.source.directory('lib/defaults'))
      // data-browser imports the repo-root logo from `../../../../logo.svg`
      // and `../../../../../logo.svg`. Browser mount sits at /app, so those
      // resolve to /logo.svg. Place the asset there.
      .withFile('/logo.svg', this.source.file('logo.svg'))
      // browser/lib/src/genesis.test.ts reads the Rust/TS/Dart shared golden
      // vectors fixture via a plain `readFileSync` (not Vite, so the
      // lib-defaults alias below doesn't apply) at
      // `../../../lib/src/genesis_test_vectors.json` from /app/lib/src —
      // same /lib collision as above, so mount just this one file rather
      // than all of repo-root lib/.
      .withFile(
        '/lib/src/genesis_test_vectors.json',
        this.source.file('lib/src/genesis_test_vectors.json'),
      )
      // browser/lib/src/loro-compat.test.ts reads the Rust-written Loro
      // fixtures and compares the loro-crdt version with Cargo.lock's, both
      // by repository-root path. Same /lib collision: mount only those.
      .withDirectory(
        '/lib/test_files/loro-compat',
        this.source.directory('lib/test_files/loro-compat'),
      )
      .withFile('/Cargo.lock', this.source.file('Cargo.lock'))
      // Fixtures shared by the Rust and TS twins (class constraints, lenses,
      // JSON Schema interop, schema lockfiles), read by repository-root
      // path. Same /lib collision: mount only that directory.
      .withDirectory(
        '/lib/tests/fixtures',
        this.source.directory('lib/tests/fixtures'),
      )
      // Tests read shared fixtures directly from the repository-root paths.
      // Include the manifest and planner corpus as well as pairing fixtures.
      .withDirectory('/testdata', this.source.directory('testdata'))
      // Mount only the required file under /lib to preserve OS libraries.
      .withFile(
        '/lib/defaults/tasks.json',
        this.source.file('lib/defaults/tasks.json'),
      )
      // browser/e2e/tests/apps.spec.ts serves this checkout's embedded app SDK
      // as a fixture, read with a plain `readFileSync` at
      // `../../../server/src/plugins/assets/view-client.js`. From /app/e2e/tests
      // that resolves to /server/..., and the Rust tree is not mounted here, so
      // mount just this one file.
      .withFile(
        '/server/src/plugins/assets/view-client.js',
        this.source.file('server/src/plugins/assets/view-client.js'),
      );

    return sourceContainer;
  }

  @func()
  private jsBuild(e2e: boolean = false): Container {
    // Only builds depend on WASM. Static lint must not wait for Rust compilation.
    let buildContainer = this.jsSource()
      .withDirectory('/app/data-browser/public/wasm', this.wasmBuild())
      .withEnvVariable('SKIP_WASM_BUILD', '1');

    if (e2e) {
      // Surfaces /app/dev-drive and /app/prunetests in the production
      // build the e2e tests run against. See `devRoutesEnabled()` in
      // data-browser/src/config.ts.
      buildContainer = buildContainer.withEnvVariable('VITE_E2E', 'true');
      // Nothing else is baked in: the plugin catalog URL is seeded into
      // localStorage by playwright, so this bundle is the same one a non-e2e
      // build produces apart from the dev routes.
    }

    return buildContainer.withExec(['pnpm', 'run', 'build']);
  }

  @func()
  /** Builds the Rust server binary on the host architecture */
  rustBuild(
    @argument() release: boolean = true,
    @argument() target: string = 'x86_64-unknown-linux-musl',
    @argument() e2e: boolean = false,
  ): Container {
    const source = this.source;

    const image = TARGET_IMAGE_MAP[target as keyof typeof TARGET_IMAGE_MAP];

    // musl-cross: CARGO_HOME=/root/.cargo (NOT /usr/local/cargo).
    const rustContainer = this.withCargoHomeCache(
      dag
        .container()
        .from(image)
        .withExec(['apt-get', 'update', '-qq'])
        .withExec(['apt', 'install', '-y', 'nasm', 'protobuf-compiler']),
      CARGO_HOME_MUSL,
    )
      .withExec(['rustup', 'target', 'add', target])
      .withExec(['rustup', 'component', 'add', 'clippy'])
      .withExec(['rustup', 'component', 'add', 'rustfmt']);
    // cargo-nextest used to be installed here, but recent versions need
    // a newer toolchain than the musl-cross image ships and a USDT crate
    // refuses to compile on this target. Moved to `rustTest()` so the
    // build / clippy / fmt / atomicService paths don't pay that cost.

    const sourceContainer = rustContainer
      .withFile('/code/Cargo.toml', source.file('Cargo.toml'))
      .withFile('/code/Cargo.lock', source.file('Cargo.lock'))
      .withFile('/code/Cross.toml', source.file('Cross.toml'))
      // Nextest reads `.config/nextest.toml` from the workspace root.
      // Without this the override that bumps the flaky search test's
      // retries silently doesn't apply — symptom: dagger reports a hard
      // FAIL with no `FLAKY` indicator while the same test recovers
      // locally on retry.
      .withFile(
        '/code/.config/nextest.toml',
        source.file('.config/nextest.toml'),
      )
      // Cargo validates every workspace member listed in Cargo.toml, so
      // mount all of them — not just the server/lib/cli we actually
      // build.
      .withDirectory('/code/server', source.directory('server'))
      .withDirectory('/code/lib', source.directory('lib'))
      .withDirectory('/code/plugin-runtime', source.directory('plugin-runtime'))
      .withDirectory('/code/cli', source.directory('cli'))
      .withDirectory('/code/desktop', source.directory('desktop'))
      .withDirectory('/code/wasm', source.directory('wasm'))
      .withDirectory(
        '/code/plugin-examples',
        source.directory('plugin-examples'),
      )
      .withDirectory('/code/atomic-plugin', source.directory('atomic-plugin'))
      .withDirectory('/code/tools', source.directory('tools'))
      // See the slim container above: the form validation cases are shared
      // with the browser and `include_str!`d by the Rust tests.
      .withFile(
        '/code/browser/form-renderer/shared/validation-cases.json',
        source.file('browser/form-renderer/shared/validation-cases.json'),
      )
      .withMountedCache('/code/target', this.targetCache('rust-target-v3'))
      .with(touchWorkspaceSources)
      .withWorkdir('/code')
      .withExec(['cargo', 'fetch', '--locked']);

    const jsContainer = this.jsBuild(e2e);
    const formAppDist = jsContainer.directory('/app/form-app/dist');
    // The published-form runtime (`browser/form-app`) is a SECOND bundle,
    // separate from the data-browser one. `server/build.rs::copy_form_assets`
    // copies it from `../browser/form-app/dist` into
    // `assets_tmp/form-assets/`, which `handlers/form.rs` `include_str!`s and
    // `static_files::generate()` serves at `/form-assets/*`. Mounting only
    // `data-browser/dist` left that path absent, so every dagger-built server
    // — the e2e one AND the release binary this same function produces —
    // embedded build.rs's placeholder shell: `/form/{id}` answered with an
    // inert "form runtime not built" page carrying no <script>. Silent,
    // because a missing form-app build is only a `cargo:warning` (it has to
    // be: the fmt/clippy/nextest containers stub `assets_tmp` and run no JS
    // build at all).
    //
    // Both halves are needed. The mount under `/code/browser` is what
    // `copy_form_assets` reads — without it, a build.rs that DOES run
    // overwrites any bundle we place with the placeholder. Pre-placing the
    // same bundle inside `assets_tmp` covers the opposite case: `/code/target`
    // is a cache volume shared across runs, and cargo will happily treat the
    // build script as fresh (replaying its stored output) while still
    // recompiling the lib — leaving `include_str!` to read whatever the
    // mounted `assets_tmp` holds.
    //
    // Only `dist` goes under `/code/browser`, deliberately: mounting
    // `form-app/src` too would add JS sources to what `should_build()`
    // compares.
    //
    // Even so, that mount is what creates `/code/browser` in this container,
    // so `build.rs` no longer takes its "no browser folder, skip the JS
    // build" path. It finds no `data-browser/dist` but does find its other
    // watched sources (`lib/src`, `wasm/src`), and runs `pnpm install`, which
    // this container does not have (run 36717450608). The JS is already
    // built above and placed in `assets_tmp`, so say so: with
    // `ATOMICSERVER_SKIP_JS_BUILD`, `build.rs` leaves the mounted
    // `assets_tmp` as it is and still refreshes `form-assets/` from the
    // mounted `form-app/dist`.
    const assetsDir = jsContainer
      .directory('/app/data-browser/dist')
      .withDirectory('form-assets', formAppDist);
    const containerWithAssets = sourceContainer
      .withDirectory('/code/server/assets_tmp', assetsDir)
      .withDirectory('/code/browser/form-app/dist', formAppDist)
      .withEnvVariable('ATOMICSERVER_SKIP_JS_BUILD', 'true');

    // Scope the build to `atomic-server` so cargo doesn't try to build
    // workspace siblings like the wasm cdylib plugin examples — which
    // can't be compiled for the host musl target.
    // `e2e` selects the `e2e` cargo profile (see the workspace Cargo.toml):
    // the debug build's behaviour — assertions and overflow checks included —
    // at an optimisation level where commit round-trips stop dominating, and
    // cheap enough to compile that Playwright is not left waiting on LTO.
    const buildArgs = e2e
      ? ['cargo', 'build', '--locked', '--profile', 'e2e', '-p', 'atomic-server']
      : release
        ? ['cargo', 'build', '--locked', '--release', '-p', 'atomic-server']
        : ['cargo', 'build', '--locked', '-p', 'atomic-server'];

    // ⚠️ PRODUCTION IMPACT, not just CI plumbing (2026-07-02): this
    // function backs BOTH the e2e test server (atomicService) AND the real
    // deploy binary (deployServer -> rustBuildRelease -> here, shipped via
    // SSH/rsync by deployment.yml). This carve-out means the actual
    // deployed x86_64-unknown-linux-musl binary now ALSO loses
    // vector-search, not just test builds.
    //
    // Root cause: the local fastembed/ORT vector-search stack does not ship
    // ONNX Runtime binaries for musl targets at all — `ort`'s `cuda`
    // feature (requested unconditionally alongside `coreml`/`directml` in
    // server/Cargo.toml) has no prebuilt binary for `cu12` on musl, x86_64
    // included. Previously only special-cased for aarch64 — x86_64 was
    // assumed fine but had simply never been exercised: this whole CI
    // pipeline never got far enough to reach `deployServer`'s build before
    // 2026-07-02's fixes, so it's unknown whether the currently-deployed
    // production binary already lacks vector-search (this build failing)
    // or ships some other way that avoids this path entirely.
    //
    // This is a deliberate, explicitly-approved stopgap, not the real fix.
    // The real fix is making `ort`'s `cuda`/`coreml`/`directml` features
    // conditional per-target in server/Cargo.toml (each is only valid on
    // one platform anyway) so the dependency spec matches reality instead
    // of silently dropping a whole feature area on affected targets. No
    // dedicated tracking doc yet — this comment + the git history on this
    // line are the record until one exists. Before removing this carve-out,
    // confirm the currently-deployed binary's actual feature set first
    // (see the paragraph above — that's still unknown).
    //
    // Same fix as `rustChecksContainer`'s clippy/test path and
    // `rustBuildSlim`'s glibc path (different symptom there — ABI mismatch,
    // not a missing binary — same root cause).
    //
    // All server builds include `wasm-plugins`: plugin handlers are compiled
    // unconditionally, and the E2E suite also executes server-side plugins.
    // `vector-search` remains excluded because of the ort/musl gap above.
    let wasmPluginsEnabled = false;
    if (target.includes('musl')) {
      if (e2e) {
        buildArgs.push(
          '--no-default-features',
          '--features',
          'https,wasm-plugins',
        );
        wasmPluginsEnabled = true;
      } else {
        buildArgs.push(
          '--no-default-features',
          '--features',
          'light,wasm-plugins',
        );
        wasmPluginsEnabled = true;
      }
    }
    // A named profile lands in `target/<triple>/<profile>/`, not `release/`.
    const targetPath = e2e
      ? `/code/target/${target}/e2e/atomic-server`
      : release
        ? `/code/target/${target}/release/atomic-server`
        : `/code/target/${target}/debug/atomic-server`;

    // `wasm-plugins`'s build.rs compiles `atomic-plugin-runtime` for
    // `wasm32-wasip2` as a nested `cargo build`, separate from the rustc
    // that's already on this image. Without the target's std lib installed,
    // that nested build fails and build.rs treats it as "plugins are an
    // optional degradation" — it swallows the failure and ships a server
    // with an empty embedded runtime instead of erroring the build. Every
    // e2e test that actually exercises server-side plugin execution
    // (this one and `plugin.spec.ts`) then hangs until timeout on a 500
    // from `/plugin-run`, with nothing in the build log to point at why.
    // `rustTest()` already installs this target for the same reason —
    // same fix, applied where the e2e server binary is actually built.
    const containerReadyToBuild = wasmPluginsEnabled
      ? containerWithAssets
          .withExec(['rustup', 'target', 'add', 'wasm32-wasip2'])
          .withEnvVariable('ATOMICSERVER_REQUIRE_PLUGIN_RUNTIME', 'true')
      : containerWithAssets;

    return (
      containerReadyToBuild
        .withExec(buildArgs)
        // .withExec([targetPath, "--version"])
        .withExec(['cp', targetPath, '/atomic-server-binary'])
    );
  }

  @func()
  /** Returns the release binary */
  rustBuildRelease(
    @argument() target: string = 'x86_64-unknown-linux-musl',
  ): File {
    const container = this.rustBuild(true, target);

    return container.file('/atomic-server-binary');
  }

  /**
   * Source-only rust container for `cargo fmt --check` / `cargo clippy`
   * / `cargo nextest run`. Same workspace inputs as {@link rustBuild}
   * but **without** the data-browser asset bundle (`assets_tmp`) and
   * without `cargo build`. The asset bundle was a hidden invalidation
   * trigger: any JS-source change rebuilt the assets, which busted the
   * dagger op-cache for fmt/clippy/test even though those steps don't
   * read the bundle. Splitting them off lets a JS-only commit cache-
   * hit through the entire rust pipeline.
   *
   * Uses its own `rust-checks-target` cache volume so it shares
   * incremental compile artifacts across fmt → clippy → test (they run
   * sequentially in `ci`) without contending with the release-binary
   * build's `rust-target`.
   */
  private rustChecksContainer(): Container {
    const source = this.source;
    const image = TARGET_IMAGE_MAP['x86_64-unknown-linux-musl'];

    // musl-cross: CARGO_HOME=/root/.cargo (NOT /usr/local/cargo). Mounting
    // the bookworm path here was a silent miss — every CI run re-ran
    // `Downloading crates ...` for nextest/clippy/fmt.
    return (
      this.withCargoHomeCache(
        dag
          .container()
          .from(image)
          .withExec(['apt-get', 'update', '-qq'])
          // `protobuf-compiler` gives `protoc`, needed by `lance-encoding`'s
          // build script (a transitive dep via the vector-search feature) —
          // without it `cargo fetch`-triggered builds under this container
          // (nextest, clippy) fail with "Could not find `protoc`". Matches
          // `rustBuild()`'s apt list; this container split off from it later
          // and the package was missed.
          .withExec(['apt', 'install', '-y', 'nasm', 'protobuf-compiler']),
        CARGO_HOME_MUSL,
      )
        .withExec(['rustup', 'target', 'add', 'x86_64-unknown-linux-musl'])
        .withExec(['rustup', 'component', 'add', 'clippy'])
        .withExec(['rustup', 'component', 'add', 'rustfmt'])
        .withFile('/code/Cargo.toml', source.file('Cargo.toml'))
        .withFile('/code/Cargo.lock', source.file('Cargo.lock'))
        .withFile('/code/Cross.toml', source.file('Cross.toml'))
        .withFile(
          '/code/.config/nextest.toml',
          source.file('.config/nextest.toml'),
        )
        // server/tests/it/iroh_pairing.rs reads the pairing contract fixture
        // relative to CARGO_MANIFEST_DIR (`../testdata/pairing-request.json`
        // from /code/server). It is the shared Rust/TS contract file, so the
        // JS container mounts it too — see the identical mount in
        // `jsBuild()`. Without it the test fails with a bare NotFound.
        .withFile(
          '/code/testdata/pairing-request.json',
          source.file('testdata/pairing-request.json'),
        )
        // server/src/plugins/plugin.rs and handlers/plugin_release_test.rs
        // `include_bytes!` the Playwright suite's plugin zip, which is the one
        // packaged plugin both sides test against. Nothing else from
        // `browser/` belongs in this container, and mounting the tree would
        // make every front-end edit invalidate the Rust layer, so mount the
        // single file. Same reasoning as the pairing-contract fixture above.
        .withFile(
          '/code/browser/e2e/tests/fixtures/test-plugin.zip',
          source.file('browser/e2e/tests/fixtures/test-plugin.zip'),
        )
        // `atomic_lib`'s tests `include_str!` the browser copy of the v2
        // signature vectors to catch the two copies drifting apart.
        .withFile(
          '/code/browser/lib/src/authentication_v2_vectors.json',
          source.file('browser/lib/src/authentication_v2_vectors.json'),
        )
        // server/src/forms.rs `include_str!`s the shared form validation
        // cases (also read by the TypeScript form-renderer tests). Mount only
        // that file, for the same reason as the plugin zip above.
        .withFile(
          '/code/browser/form-renderer/shared/validation-cases.json',
          source.file('browser/form-renderer/shared/validation-cases.json'),
        )
        .withDirectory('/code/server', source.directory('server'))
        .withDirectory('/code/integrations', source.directory('integrations'))
        .withDirectory('/code/testdata', source.directory('testdata'))
        .withDirectory('/code/lib', source.directory('lib'))
        .withDirectory(
          '/code/plugin-runtime',
          source.directory('plugin-runtime'),
        )
        .withDirectory('/code/cli', source.directory('cli'))
        .withDirectory('/code/desktop', source.directory('desktop'))
        .withDirectory('/code/wasm', source.directory('wasm'))
        .withDirectory(
          '/code/plugin-examples',
          source.directory('plugin-examples'),
        )
        .withDirectory('/code/atomic-plugin', source.directory('atomic-plugin'))
        .withDirectory('/code/tools', source.directory('tools'))
        .withMountedCache('/code/target', this.targetCache('rust-checks-target-v3'))
        .with(touchWorkspaceSources)
        .withWorkdir('/code')
        // build.rs in atomic-server wants to bundle a JS dist. Skip it —
        // fmt/clippy/test don't need it and including the bundle would
        // re-introduce the JS-source dependency we just removed.
        .withEnvVariable('ATOMICSERVER_SKIP_JS_BUILD', 'true')
        .withExec(['mkdir', '-p', '/code/server/assets_tmp'])
        .withExec([
          'sh',
          '-c',
          'echo "<html><body>checks stub</body></html>" > /code/server/assets_tmp/index.html',
        ])
        .withExec(['cargo', 'fetch', '--locked'])
    );
  }

  @func()
  rustTest(): Promise<string> {
    return (
      this.rustChecksContainer()
        .withExec(['rustup', 'target', 'add', 'wasm32-wasip2'])
        .withEnvVariable('ATOMICSERVER_REQUIRE_PLUGIN_RUNTIME', 'true')
        // Persist nextest in the shared cargo-bin volume. Previously the
        // curl install sat *after* the source mount, so every Rust source
        // change re-downloaded it. The `linux-musl` URL is required: the
        // default `linux` artifact is glibc and silently exits 1 on the
        // musl-cross image. Bundle install + run so a cleared volume
        // can't leave nextest missing on a dagger layer-cache hit.
        //
        // Prepend to PATH in-shell — do NOT replace the container PATH.
        // The musl-cross image needs `/usr/local/musl/bin` (for
        // `x86_64-unknown-linux-musl-gcc`); a hardcoded PATH drop caused
        // "linker not found" while compiling plugin-example tests.
        //
        // The install unpacks into a staging directory and renames the binary
        // into place, because the volume is Shared and two runs on one engine
        // race on it. `tar` straight into `$BIN_DIR` creates the executable
        // before it has finished writing it, so the other run's `-x` test
        // passes, it skips the install, and its `cargo nextest` exec of a
        // file still open for writing fails with "Text file busy
        // (os error 26)" before any test body runs. A rename is atomic, so a
        // concurrent run sees either no binary or a complete one.
        .withMountedCache('/opt/cargo-bin', dag.cacheVolume('cargo-bin'), {
          sharing: CacheSharingMode.Shared,
        })
        // `--exclude atomic-server-tauri`: same reason as `rustClippy` —
        // the Tauri desktop crate needs system libs (glib-2.0, pkg-config)
        // that aren't installed in the musl-cross CI image.
        //
        // `--no-default-features --features light`: `atomic-server`'s
        // default features include `vector-search`, which pulls in `ort`
        // with `cuda`/`coreml`/`directml` all requested unconditionally.
        // `ort` ships no prebuilt binary for musl + cuda, so the workspace
        // fails to even compile here. Mirrors the existing
        // `aarch64-unknown-linux-musl` release-build carve-out in
        // `rustBuild()` (same underlying ort/musl gap, same fix). Verified
        // locally: `--no-default-features --features light` at `--workspace`
        // scope only strips `atomic-server`'s own defaults — other members
        // don't define a `light` feature and are unaffected.
        //
        // `--build-jobs` / `--test-threads` / `--retries`: from
        // `--host-profile` (mancave hot / hosted quiet). The toml still
        // caps `it` at 2 and serializes `iroh_pairing::*`.
        .withExec([
          'sh',
          '-c',
          'export PATH="/opt/cargo-bin/bin:$PATH" && ' +
            'BIN_DIR=/opt/cargo-bin/bin && mkdir -p "$BIN_DIR" && ' +
            'if [ ! -x "$BIN_DIR/cargo-nextest" ]; then ' +
            'STAGE=$(mktemp -d "$BIN_DIR/.nextest-XXXXXX") && ' +
            'curl -LsSf https://get.nexte.st/latest/linux-musl | tar zxf - -C "$STAGE" && ' +
            'mv -f "$STAGE/cargo-nextest" "$BIN_DIR/cargo-nextest" && ' +
            'rm -rf "$STAGE"; fi && ' +
            'cargo nextest run --locked --workspace --exclude atomic-server-tauri ' +
            '--no-default-features --features light,wasm-plugins ' +
            `--build-jobs ${this.hostKnobs.nextestBuildJobs} ` +
            `--test-threads ${this.hostKnobs.nextestTestThreads} ` +
            `--retries ${this.hostKnobs.nextestRetries}`,
        ])
        .stdout()
    );
  }

  @func()
  rustClippy(): Promise<string> {
    // Exclude `desktop` (Tauri) — its build pulls in `glib-sys`, which
    // requires `pkg-config` + `glib-2.0` dev libraries that the musl-cross
    // CI image doesn't carry. The desktop crate is built separately via the
    // Tauri toolchain on platforms that have those system libs.
    //
    // Drop `--all-features` to keep the build inside what the musl-cross
    // image can satisfy: enabling every feature pulls in optional deps
    // (e.g. `openssl-sys` via some opentelemetry / TLS feature) that need
    // system OpenSSL we don't ship. Default features are what the release
    // binary already builds with.
    //
    // `--no-default-features --features light,wasm-plugins`: same
    // ort/musl/cuda gap as `rustTest` above — `vector-search`'s `ort` dep has
    // no prebuilt binary for this target, so even a lint-only pass can't
    // compile it. Vector-search-gated code isn't clippy-checked on this path;
    // plugin code is included because rustTest uses the same feature set.
    return this.rustChecksContainer()
      .withExec([
        'cargo',
        'clippy',
        '--locked',
        '--workspace',
        '--exclude',
        'atomic-server-tauri',
        '--no-deps',
        '--all-targets',
        '--no-default-features',
        '--features',
        'light,wasm-plugins',
      ])
      .stdout();
  }

  @func()
  rustFmt(): Promise<string> {
    // Fmt only reads source — runs against the source-only checks
    // container so a JS-source change can't bust its dagger op-cache.
    return this.rustChecksContainer()
      .withExec(['cargo', 'fmt', '--check'])
      .stdout();
  }

  // @func()
  // /** Doesn't work on M1 macs */
  // rustCrossBuild(@argument() target: string): Container {
  //   let engineSvc = dag.docker().engine();
  //   const source = this.source;

  //   const sourceContainer = dag
  //     // To allow cross-compilation to work on M1 macs
  //     .container({ platform: "linux/amd64" as Platform })
  //     .from("docker:cli")
  //     .withServiceBinding("docker", engineSvc)
  //     .withEnvVariable("DOCKER_HOST", "tcp://docker:2375")
  //     .withExec(["docker", "ps"])
  //     .withExec([
  //       "apk",
  //       "add",
  //       "--no-cache",
  //       // For installing rust
  //       "curl",
  //       // CC linker deps, compiling cross
  //       "build-base",
  //       "gcc",
  //       "musl-dev",
  //       "cmake",
  //     ])
  //     .withExec([
  //       "sh",
  //       "-c",
  //       "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable",
  //     ])
  //     .withEnvVariable(
  //       "PATH",
  //       "/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  //     )
  //     .withExec(["docker", "ps"])
  //     .withExec(["cargo", "install", "cross"])
  //     .withExec(["rustup", "target", "add", target])
  //     .withExec([
  //       "rustup",
  //       "toolchain",
  //       "add",
  //       "stable-x86_64-unknown-linux-gnu",
  //       "--profile",
  //       "minimal",
  //       "--force-non-host",
  //     ])
  //     .withFile("/home/rust/src/Cargo.toml", source.file("Cargo.toml"))
  //     .withFile("/home/rust/src/Cargo.lock", source.file("Cargo.lock"))
  //     .withDirectory("/home/rust/src/server", source.directory("server"))
  //     .withDirectory("/home/rust/src/lib", source.directory("lib"))
  //     .withDirectory("/home/rust/src/cli", source.directory("cli"))
  //     .withMountedCache("/home/rust/src/target", dag.cacheVolume("rust-target"))
  //     .withWorkdir("/home/rust/src");

  //   // Include frontend assets for the server build
  //   const browserDir = this.jsBuild().directory("/app/data-browser/dist");
  //   const containerWithAssets = sourceContainer.withDirectory(
  //     "/home/rust/src/server/assets_tmp",
  //     browserDir
  //   );

  //   // Build using native cargo with target specification
  //   const binaryPath = `./target/${target}/release/atomic-server`;

  //   return containerWithAssets
  //     .withExec(["cross", "build", "--target", target, "--release"])
  //     .withExec(["cp", binaryPath, "/atomic-server-binary"]);
  // }

  /** Diagnostic: navigate Playwright to /app/dev-drive against the atomic
   *  service and dump console messages + network failures. */
  @func()
  async probeDevDrive(): Promise<string> {
    return dag
      .container()
      .from(`mcr.microsoft.com/playwright:${PLAYWRIGHT_VERSION}`)
      .withExec([
        'npm',
        'install',
        '-g',
        `playwright@${PLAYWRIGHT_PACKAGE_VERSION}`,
      ])
      .withExec(['npx', 'playwright', 'install', 'chromium'])
      .withServiceBinding('atomic', this.atomicService(true))
      .withNewFile(
        '/probe.js',
        `const { chromium } = require('/usr/lib/node_modules/playwright');
(async () => {
  const browser = await chromium.launch({
    args: ['--host-resolver-rules=MAP atomic.localhost ${ATOMIC_DOMAIN}'],
  });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const logs = [];
  page.on('console', m => logs.push('[console:' + m.type() + '] ' + m.text()));
  page.on('pageerror', e => logs.push('[pageerror] ' + e.message));
  page.on('requestfailed', r => logs.push('[reqfail] ' + r.url() + ' ' + r.failure()?.errorText));
  try {
    await page.goto('http://atomic.localhost:9883/app/dev-drive', { waitUntil: 'networkidle', timeout: 20000 });
  } catch (e) {
    logs.push('[goto error] ' + e.message);
  }
  await new Promise(r => setTimeout(r, 15000));
  logs.push('[final url] ' + page.url());
  const crypto = await page.evaluate(() => ({
    isSecureContext: window.isSecureContext,
    hasSubtle: !!(window.crypto && window.crypto.subtle),
    hasDigest: !!(window.crypto && window.crypto.subtle && window.crypto.subtle.digest),
  }));
  logs.push('[crypto] ' + JSON.stringify(crypto));
  console.log(logs.join('\\n'));
  await browser.close();
})();`,
      )
      .withExec([
        'sh',
        '-c',
        `for i in $(seq 1 20); do curl -fsS http://${ATOMIC_DOMAIN}:9883/setup -H 'Accept: application/ad+json' && break || sleep 1; done; node /probe.js`,
      ])
      .stdout();
  }

  /** Diagnostic: curl `/app/dev-drive` against the atomic service to see
   *  what the e2e tests actually receive. */
  @func()
  async probeAtomicService(): Promise<string> {
    return dag
      .container()
      .from('alpine:latest')
      .withExec(['apk', 'add', '--no-cache', 'curl'])
      .withServiceBinding('atomic', this.atomicService())
      .withExec([
        'sh',
        '-c',
        `for i in $(seq 1 20); do curl -fsS http://${ATOMIC_DOMAIN}:9883/setup -H 'Accept: application/ad+json' && break || sleep 1; done; ` +
          `echo '== /app/dev-drive headers ==='; ` +
          `curl -sS -D - -o /dev/null -H 'Accept: text/html' http://${ATOMIC_DOMAIN}:9883/app/dev-drive; ` +
          `echo '== /assets/index js HEAD ==='; ` +
          `JS=$(curl -sS -H 'Accept: text/html' http://${ATOMIC_DOMAIN}:9883/app/dev-drive | grep -oE 'src="/assets/index[^"]+"' | head -1 | sed 's/src="//;s/"//'); ` +
          `echo "JS path: $JS"; ` +
          `curl -sS -D - -o /dev/null http://${ATOMIC_DOMAIN}:9883$JS; ` +
          `echo '== /app/welcome status ==='; ` +
          `curl -sS -o /dev/null -w 'status=%{http_code}\\n' -H 'Accept: text/html' http://${ATOMIC_DOMAIN}:9883/app/welcome`,
      ])
      .stdout();
  }

  @func()
  /** Returns a Service running atomic-server for use in tests */
  atomicService(
    @argument() e2e: boolean = false,
    /** Distinct service state for an E2E shard; empty keeps the default service. */
    @argument() instance: string = '',
  ): Service {
    if (instance && !/^[a-z0-9-]{1,48}$/.test(instance)) {
      throw new Error(
        'Service instance must use 1-48 lowercase letters, digits or hyphens',
      );
    }
    // E2E builds with the `e2e` cargo profile (workspace Cargo.toml): a debug
    // server costs ~7x per commit round-trip, and four of them run alongside
    // eight browsers, so the slowness lands as timing failures. Full
    // `--release` was reverted once for 15-30 min of cold compile; the `e2e`
    // profile drops LTO and the single codegen unit, which is where that time
    // went. Deploy still goes through `rustBuildRelease` (release=true).
    const atomicServerBinary = this.rustBuild(
      !e2e,
      'x86_64-unknown-linux-musl',
      e2e,
    ).file('/atomic-server-binary');

    let runtime = dag
      .container()
      .from('alpine:latest')
      .withFile('/atomic-server-bin', atomicServerBinary, {
        permissions: 0o755,
      })
      .withEnvVariable('ATOMIC_DOMAIN', ATOMIC_DOMAIN)
      .withEnvVariable('ATOMIC_INITIALIZE', 'true')
      .withExposedPort(9883)
      .withEntrypoint(['/atomic-server-bin']);

    if (e2e)
      runtime = runtime
        // Website publishing is off until the server is given a site origin,
        // and the website specs then get a "hosting is disabled" toast that
        // also sits over the preview and swallows clicks meant for it. The
        // server asks for a separate `.localhost` origin in development; this
        // is that, and it has to stay outside the API domain.
        .withEnvVariable('ATOMIC_WEBSITE_ORIGIN', 'http://sites.localhost:9883')
        // The name the server answers to, which until now was not the name it
        // is addressed by. `ATOMIC_DOMAIN` above is the dagger hostname, and
        // the server was given the same string, so its configured origin was
        // `http://atomic:9883` while every browser-created subject carried
        // `http://atomic.localhost:9883`. Those two are compared as authorities
        // in `Subject::from_raw`, where `atomic.localhost:9883` matches neither
        // `atomic:9883` nor the `.atomic:9883` suffix case, so the server read
        // its own subjects as somebody else's:
        //
        //   from_raw(".../releases/blake3:1a0b3fbb", Some("http://atomic:9883"))
        //     -> is_local false
        //   from_raw(".../releases/blake3:1a0b3fbb", Some("http://atomic.localhost:9883"))
        //     -> is_local true
        //
        // Splitting the two lets the server know its own name while dagger
        // keeps addressing the container as `atomic`. Routing does not move
        // with it: `map_request_subject` (lib/src/db.rs) only re-routes a host
        // explicitly bound to a Drive, and `atomic` is not bound, so the
        // containers that curl `http://atomic:9883` are unaffected.
        .withEnvVariable('ATOMIC_DOMAIN', 'atomic.localhost')
        .withEntrypoint([
          'sh',
          '-c',
          // Makes `atomic.localhost` resolve inside this container. RFC 6761
          // gives `.localhost` to loopback, but that is a rule browsers and
          // Node implement and glibc does not: with `hosts: files dns` the
          // name does not resolve at all, and anything here that looks it up
          // fails before a request goes out.
          //
          // This is no longer about `plugin.spec.ts:26`. That was fixed by
          // giving the server its own `ATOMIC_DOMAIN` above, so it reads its
          // own subjects locally instead of fetching them, and the run after
          // that change was green on `:26` and `installation-recovery:96`.
          // What this line covers now is the server resolving any subject
          // genuinely on another host. That is a wider scope than the SSRF
          // escape hatch removed alongside it, which reached only five Rust
          // call sites, so the two were not a pair despite arriving in one
          // commit.
          //
          // Written at start rather than baked in, because the runtime mounts
          // its own `/etc/hosts` over the image's. The server binds `::`, so
          // once the name resolves it reaches itself.
          'echo "127.0.0.1 atomic.localhost" >> /etc/hosts; ' +
            'exec /atomic-server-bin',
        ]);

    // Dagger deduplicates identical services, including their writable state.
    // Vary only the runtime graph: every shard still shares the binary build.
    if (instance)
      runtime = runtime.withEnvVariable('E2E_SERVICE_INSTANCE', instance);

    const service = runtime.asService();
    // Dagger appends its own DNS suffix. Let it generate short unique names
    // for shards; their consumers still bind the stable `atomic` alias.
    return instance ? service : service.withHostname(ATOMIC_DOMAIN);
  }

  /**
   * Shared Playwright + workspace install for e2e shards. No service binding
   * and no test run yet — each shard forks from this and binds its own
   * `atomicService` so 4 servers don't share state.
   */
  private e2eBaseContainer(): Container {
    // Workspace deps only — SPA assets come from `atomicService(true)` →
    // `rustBuild(..., e2e=true)` → `jsBuild(true)`.
    const browserContainer = this.jsBuild();

    // Reuses the npm-global volume so `netlify-cli` isn't re-downloaded when
    // docs deploy already warmed it.
    const playwrightContainer = dag
      .container()
      .from(`mcr.microsoft.com/playwright:${PLAYWRIGHT_VERSION}`)
      .withMountedCache('/opt/npm-global', dag.cacheVolume('npm-global'))
      .withMountedCache('/root/.npm', dag.cacheVolume('npm-cache'))
      .withEnvVariable('NPM_CONFIG_PREFIX', '/opt/npm-global')
      .withEnvVariable(
        'PATH',
        `${PNPM_BIN_DIR}:/opt/npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
      )
      .withExec([
        '/bin/sh',
        '-c',
        `curl -fsSL https://get.pnpm.io/install.sh | env PNPM_VERSION=${PNPM_VERSION} ENV="$HOME/.shrc" SHELL="$(which sh)" sh - && ` +
          `export PATH=${PNPM_BIN_DIR}:/opt/npm-global/bin:$PATH && ` +
          '/bin/apt update && /bin/apt install -y zip && ' +
          'if [ ! -x /opt/npm-global/bin/netlify ]; then npm install -g netlify-cli --quiet; fi && netlify --version',
      ]);

    // Bug fix (2026-07-02): mount the full pnpm workspace before
    // `pnpm install` — see git history for ERR_PNPM_WORKSPACE_PKG_NOT_FOUND.
    return (
      playwrightContainer
        .withEnvVariable('CI', 'true')
        .withEnvVariable(
          'ATOMIC_E2E_CLONE_SESSION',
          this.e2eCloneSessions ? '1' : '0',
        )
        // Playwright-run knobs — see `e2eRunKnobs` / `--playwright-mode`. Isolated
        // from `hostKnobs` so a light suite does not change nextest width.
        .withEnvVariable('PLAYWRIGHT_WORKERS', this.e2eRun.workers)
        .withEnvVariable('PLAYWRIGHT_RETRIES', this.e2eRun.retries)
        .withFile(
          '/app/package.json',
          browserContainer.file('/app/package.json'),
        )
        .withFile(
          '/app/pnpm-lock.yaml',
          browserContainer.file('/app/pnpm-lock.yaml'),
        )
        .withFile(
          '/app/pnpm-workspace.yaml',
          browserContainer.file('/app/pnpm-workspace.yaml'),
        )
        .withDirectory(
          '/app/patches',
          browserContainer.directory('/app/patches'),
        )
        .withDirectory(
          '/app/e2e',
          this.source
            .directory('browser/e2e')
            .withoutDirectory('tests')
            .withoutDirectory('playwright-report')
            .withoutDirectory('node_modules')
            .withoutDirectory('test-results'),
        )
        .withDirectory('/app/cli', browserContainer.directory('/app/cli'))
        .withDirectory('/app/react', browserContainer.directory('/app/react'))
        .withDirectory('/app/svelte', browserContainer.directory('/app/svelte'))
        .withDirectory(
          '/app/create-template',
          browserContainer.directory('/app/create-template'),
        )
        .withDirectory('/app/lib', browserContainer.directory('/app/lib'))
        .withDirectory(
          '/app/node_modules',
          browserContainer.directory('/app/node_modules'),
        )
        // playwright.config.ts starts testdata/atomic-plugins-mock/serve.mjs
        // (../../testdata from /app/e2e) as the suite's plugin catalog.
        .withDirectory('/testdata', this.source.directory('testdata'))
        // Same shape, one file: apps.spec.ts reads the embedded app SDK with a
        // plain `readFileSync` at `../../../server/src/plugins/assets/
        // view-client.js`, which from /app/e2e/tests is /server/... . jsSource()
        // mounts it for browser/plugin's unit test, but the specs run here, in a
        // fresh Playwright image that copies only what is named, so this
        // container needs its own copy.
        .withFile(
          '/server/src/plugins/assets/view-client.js',
          this.source.file('server/src/plugins/assets/view-client.js'),
        )
        .withWorkdir('/app/e2e')
        .withMountedCache('/app/.pnpm-store', dag.cacheVolume('pnpm-store'))
        .withExec(['pnpm', 'config', 'set', 'store-dir', '/app/.pnpm-store'])
        .withExec(['pnpm', 'install'])
        // No browser cache volume: the image already carries the builds this
        // Playwright wants (see PLAYWRIGHT_VERSION), so this verifies them and
        // exits. Mounting a volume over `~/.cache/ms-playwright` did nothing —
        // the image points `PLAYWRIGHT_BROWSERS_PATH` at `/ms-playwright`.
        .withExec(['pnpm', 'exec', 'playwright', 'install'])
        .withEnvVariable('LANGUAGE', 'en_GB')
        .withEnvVariable('FRONTEND_URL', `http://atomic.localhost:9883`)
        .withEnvVariable('SERVER_URL', `http://atomic.localhost:9883`)
        .withEnvVariable('ATOMIC_SERVICE_URL', `http://${ATOMIC_DOMAIN}:9883`)
        .withEnvVariable(
          'ATOMIC_TEST_HOST_MAP',
          `MAP atomic.localhost ${ATOMIC_DOMAIN}`,
        )
        .withDirectory(
          '/app/e2e/tests',
          this.source.directory('browser/e2e/tests'),
        )
    );
  }

  /** Unique per `dagger call`; see `e2eShardContainer`. */
  private readonly e2eRunNonce = `${Date.now()}-${Math.random().toString(36).slice(2)}`;

  /** One Playwright shard against its own atomic-server service. */
  private e2eShardContainer(base: Container, shardIndex: number): Container {
    const shardCount = this.e2eRun.shardCount;

    return (
      base
        .withServiceBinding(
          'atomic',
          this.atomicService(true, `${this.e2eRunNonce}-${shardIndex}`),
        )
        .withExec([
          'sh',
          '-c',
          `for i in $(seq 1 30); do curl -fsS http://${ATOMIC_DOMAIN}:9883/setup && exit 0 || sleep 1; done; exit 1`,
        ])
        // Dagger caches an exec by its inputs, and the shard script always
        // exits 0 (the real exit code goes to a file), so a run whose sources
        // matched an earlier one replayed that run's output verbatim: a
        // workflow-only change, an empty commit or `gh run rerun` all "passed"
        // or "failed" with the previous run's exact log and shard timings. A
        // per-invocation nonce on this step makes the browsers run every time.
        // It sits after the service binding and the setup probe, so the build
        // layers above stay cached; only the Playwright exec is unique.
        .withEnvVariable('E2E_RUN_NONCE', this.e2eRunNonce)
        .withExec([
          '/bin/bash',
          '-c',
          e2eShardRunScript(this.e2eRun.grep, shardIndex, shardCount),
        ])
    );
  }

  @func()
  async endToEnd(
    @argument() netlifyAuthToken: Secret,
    /**
     * `light` = `@smoke` only. `full` (default) = every spec, matching
     * today's unfiltered suite. Workflow decides; this func does not
     * guess the git ref. See `ci()` for why this is not named `e2eMode`.
     */
    @argument() playwrightMode: string = 'full',
    /** Per-shard worker override; 0 keeps the host profile. */
    @argument() playwrightWorkers: number = 0,
    /** Number of isolated servers; 0 keeps the host profile. */
    @argument() playwrightShards: number = 0,
    /** -1 keeps the host profile; 0 exposes failures without retrying. */
    @argument() playwrightRetries: number = -1,
    /**
     * Optional Playwright regular expression for one focused browser journey.
     * A focused run stays on one server/shard, so an exact test does not run
     * alongside unrelated E2E failures.
     */
    @argument() playwrightGrep: string = '',
    /** Reuse closed worker profiles for eligible drive-scoped specs. */
    @argument() playwrightCloneSessions: boolean = false,
    /** See `ci()`. */
    @argument() resultsKey: string = '',
  ): Promise<string> {
    this.e2eCloneSessions = playwrightCloneSessions;
    // Shards × own atomic-server. Count comes from `--host-profile`
    // (Mancave hot / hosted conservative) plus `--playwright-mode` (light uses
    // fewer shards). Dagger dedupes the shared optimized `rustBuild(e2e)` /
    // base-container graph.
    this.e2eRun = overrideE2eBudget(
      e2eRunKnobs(this.hostProfile, resolveE2eMode(playwrightMode)),
      playwrightWorkers,
      playwrightShards,
      playwrightRetries,
    );
    if (playwrightGrep)
      this.e2eRun = {
        ...this.e2eRun,
        shardCount: 1,
        grep: playwrightGrep,
      };
    console.info(
      `E2E budget: ${this.e2eRun.shardCount} shards x ${this.e2eRun.workers} workers = ${this.e2eRun.shardCount * Number(this.e2eRun.workers)} browser workers; retries=${this.e2eRun.retries}; cloned profiles=${this.e2eCloneSessions}; concurrent CI cargo jobs=${this.hostKnobs.cargoBuildJobs}, nextest threads=${this.hostKnobs.nextestTestThreads}. JS/Flutter jobs also share this host.`,
    );
    const shardCount = this.e2eRun.shardCount;
    const base = this.e2eBaseContainer();
    const shardIndexes = Array.from({ length: shardCount }, (_, i) => i + 1);
    const shardContainers = shardIndexes.map(i =>
      this.e2eShardContainer(base, i),
    );

    const results = await Promise.all(
      shardContainers.map(async (container, idx) => {
        const shard = idx + 1;
        const [exitCode, testOutput] = await Promise.all([
          container.file('/test-exit-code').contents(),
          container.file('/test-output.log').contents(),
        ]);

        return {
          shard,
          exitCode: exitCode.trim(),
          testOutput,
          report: container.directory('playwright-report'),
          // Traces, screenshots and `error-context.md` per failed test. The
          // 20k-char log tail below says WHICH assertion failed; this is the
          // only thing that says why.
          testResults: container.directory('test-results'),
        };
      }),
    );

    const failed = results.filter(r => r.exitCode !== '0');
    const reportUrls: string[] = [];

    // Deploy reports sequentially — concurrent `netlify deploy` to the same
    // site races. Prefer failed shards so the error message has a URL.
    const toDeploy = failed.length > 0 ? failed : results.slice(0, 1);

    for (const r of toDeploy) {
      const deployOutput = await this.netlifyDeploy(
        r.report,
        'atomic-tests',
        netlifyAuthToken,
      );
      reportUrls.push(
        `shard ${r.shard}/${shardCount}: ${this.extractDeployUrl(deployOutput)}`,
      );
    }

    if (failed.length > 0) {
      const tails = failed
        .map(
          r =>
            `===== SHARD ${r.shard}/${shardCount} (exit ${r.exitCode}) =====\n${r.testOutput.slice(-20000)}`,
        )
        .join('\n\n');
      const contexts = (
        await Promise.all(failed.map(r => this.errorContexts(r)))
      )
        .filter(Boolean)
        .join('\n\n');
      const exported = resultsKey
        ? await this.saveTestResults(resultsKey, failed)
        : 'none kept (no --results-key)';
      throw new Error(
        `E2E tests failed on ${failed.length}/${shardCount} shard(s).\n` +
          `Reports:\n${reportUrls.join('\n')}\n` +
          `Traces: ${exported}\n\n${tails}` +
          (contexts ? `\n\n${contexts}` : ''),
      );
    }

    return reportUrls.join('\n') || 'e2e ok (no report URL)';
  }

  /**
   * Keeps failed shards' `test-results` (traces, screenshots,
   * `error-context.md`) in a cache volume under `key`, for `failedTestResults`.
   *
   * They used to leave only through the netlify report, and with
   * `NETLIFY_TOKEN` unset they were discarded with the container. A failure
   * that only happens on Mancave then left an assertion message and nothing
   * else: on 29-30 September a reload that rendered a blank page could only
   * be described, not diagnosed. `Directory.export` from inside this module
   * does not help: it writes into the function's own sandbox, not onto the
   * runner. The `ci` call fails, so it cannot return them either; a second
   * call reads them back from the volume instead.
   */
  private async saveTestResults(
    key: string,
    failed: { shard: number; testResults: Directory }[],
  ): Promise<string> {
    const safeKey = key.replace(/[^A-Za-z0-9._-]/g, '_');
    try {
      let container = dag
        .container()
        .from('alpine:latest')
        .withMountedCache('/results', dag.cacheVolume('e2e-test-results-v1'));

      for (const r of failed) {
        container = container.withDirectory(`/in/shard-${r.shard}`, r.testResults);
      }

      await container
        .withExec([
          'sh',
          '-c',
          // Keep a week of runs; the volume must not grow without bound.
          `find /results -mindepth 1 -maxdepth 1 -mtime +7 -exec rm -rf {} + ; ` +
            `rm -rf /results/${safeKey} && mkdir -p /results/${safeKey} && ` +
            `cp -r /in/. /results/${safeKey}/`,
        ])
        .sync();

      return `kept under ${safeKey}; the workflow uploads them as the e2e-test-results artifact`;
    } catch (e) {
      return `could not keep test results: ${e}`;
    }
  }

  /**
   * Named without a digit on purpose: Dagger's CLI kebab-cases `e2eTestResults`
   * to something other than `e2e-test-results` (as with `--e2e-mode`), and
   * the workflow's call failed with "unknown command" (run 36895753311).
   *
   * The traces `ci`/`endToEnd` kept for failed shards under `resultsKey`,
   * one folder per shard. Empty when nothing failed. main-ci.yml exports
   * this on failure and uploads it as an artifact.
   */
  @func()
  async failedTestResults(@argument() resultsKey: string): Promise<Directory> {
    const safeKey = resultsKey.replace(/[^A-Za-z0-9._-]/g, '_');

    return dag
      .container()
      .from('alpine:latest')
      .withMountedCache('/results', dag.cacheVolume('e2e-test-results-v1'))
      .withExec([
        'sh',
        '-c',
        `mkdir -p /out && if [ -d /results/${safeKey} ]; then cp -r /results/${safeKey}/. /out/; fi`,
      ])
      .directory('/out');
  }

  /**
   * The page snapshot Playwright writes beside each failed test.
   *
   * The stdout tail says which assertion failed; this says what the page
   * actually was at that moment, which is the difference between diagnosing a
   * CI-only failure and guessing at it. Reports go to netlify and nowhere
   * else, and `NETLIFY_TOKEN` is empty on this pipeline, so without this the
   * snapshots are simply discarded when the run ends.
   *
   * Capped per file and per shard: this lands in a CI log, and a trace dump
   * nobody scrolls through is no more useful than no trace at all.
   */
  private async errorContexts(r: {
    shard: number;
    testResults: Directory;
  }): Promise<string> {
    try {
      const paths = await r.testResults.glob('**/error-context.md');
      const bodies = await Promise.all(
        paths.slice(0, 12).map(async path => {
          const body = await r.testResults.file(path).contents();

          return `--- ${path} ---\n${condenseErrorContext(body)}`;
        }),
      );

      return bodies.length
        ? `===== SHARD ${r.shard} PAGE SNAPSHOTS =====\n${bodies.join('\n\n')}`
        : '';
    } catch (e) {
      return `===== SHARD ${r.shard}: could not read error contexts: ${e} =====`;
    }
  }

  @func()
  async deployServer(
    @argument() remoteHost: string,
    @argument() remoteUser: Secret,
    @argument() sshPrivateKey: Secret,
  ): Promise<string> {
    // Build the cross-compiled binary for x86_64-unknown-linux-musl
    const binaryFile = this.rustBuildRelease('x86_64-unknown-linux-musl');

    // Create deployment container with SSH client
    const deployContainer = dag
      .container()
      .from('alpine:latest')
      .withExec(['apk', 'add', '--no-cache', 'openssh-client', 'rsync'])
      .withFile('/atomic-server-binary', binaryFile, { permissions: 0o755 });

    // Setup SSH key
    const sshContainer = deployContainer
      .withExec(['mkdir', '-p', '/root/.ssh'])
      .withSecretVariable('SSH_PRIVATE_KEY', sshPrivateKey)
      .withExec(['sh', '-c', 'echo "$SSH_PRIVATE_KEY" > /root/.ssh/id_rsa'])
      .withExec(['chmod', '600', '/root/.ssh/id_rsa'])
      .withExec(['ssh-keyscan', '-H', remoteHost])
      .withExec([
        'sh',
        '-c',
        `ssh-keyscan -H ${remoteHost} >> /root/.ssh/known_hosts`,
      ]);

    // Transfer binary using rsync
    const transferResult = await sshContainer
      .withSecretVariable('REMOTE_USER', remoteUser)
      .withExec([
        'sh',
        '-c',
        `rsync -rltgoDzvO /atomic-server-binary $REMOTE_USER@${remoteHost}:~/atomic-server-x86_64-unknown-linux-musl`,
      ])
      .stdout();

    // Execute deployment commands on remote server
    const deployResult = await sshContainer
      .withSecretVariable('REMOTE_USER', remoteUser)
      .withExec([
        'sh',
        '-c',
        `ssh -i /root/.ssh/id_rsa $REMOTE_USER@${remoteHost} '
          mv ~/atomic-server-x86_64-unknown-linux-musl ~/atomic-server &&
          cp ~/atomic-server ~/atomic-server-$(date +"%Y-%m-%dT%H:%M:%S") &&
          systemctl stop atomic &&
          ./atomic-server export &&
          systemctl start atomic &&
          systemctl status atomic
        '`,
      ])
      .stdout();

    return `Deployment to ${remoteHost} completed successfully:\n${deployResult}`;
  }

  @func()
  async releaseAssets(): Promise<Directory> {
    const targets = Object.keys(TARGET_IMAGE_MAP);

    const builds = targets.map(target => {
      const container = this.rustBuild(true, target);

      return {
        target,
        binary: container.file('/atomic-server-binary'),
      };
    });

    // Create a directory with all the binaries
    let outputDir = dag.directory();

    for (const build of builds) {
      outputDir = outputDir.withFile(
        `atomic-server-${build.target}`,
        build.binary,
      );
    }

    return outputDir;
  }

  @func()
  /** Creates a Docker image for a specific target architecture */
  createDockerImage(
    @argument() target: string = 'x86_64-unknown-linux-musl',
  ): Container {
    const binary = this.rustBuild(true, target).file('/atomic-server-binary');

    // Map targets to their corresponding platform strings
    const platformMap = {
      'x86_64-unknown-linux-musl': 'linux/amd64' as Platform,
      'aarch64-unknown-linux-musl': 'linux/arm64' as Platform,
      'armv7-unknown-linux-musleabihf': 'linux/arm/v7' as Platform,
    };

    const platform = platformMap[target as keyof typeof platformMap];

    if (!platform) {
      throw new Error(`Unknown platform for target: ${target}`);
    }

    const innerImage = 'alpine:latest';

    // https://github.com/dagger/dagger/issues/9998
    const dir = dag.directory().withNewFile(
      'Dockerfile',
      `FROM ${innerImage}

VOLUME /atomic-storage
`,
    );

    return (
      dir
        // `Container.build` was removed in the SDK that came with the v0.21
        // engine bump — the Dockerfile build now hangs off the Directory.
        // Branch CI never runs this function (publish is develop-only), so
        // the bump's break only surfaced on the first develop run after it.
        .dockerBuild({ platform })
        // .from(innerImage)
        .withFile('/usr/local/bin/atomic-server', binary)
        .withExec(['chmod', '+x', '/usr/local/bin/atomic-server'])
        .withEntrypoint(['/usr/local/bin/atomic-server'])
        .withEnvVariable('ATOMIC_DATA_DIR', '/atomic-storage/data')
        .withEnvVariable('ATOMIC_CONFIG_DIR', '/atomic-storage/config')
        .withEnvVariable('ATOMIC_PORT', '80')
        .withExposedPort(80)
        .withDefaultArgs([])
    );
  }

  @func()
  /** Creates Docker images for all supported architectures */
  async createDockerImages(
    @argument() tags: string[] = ['develop'],
  ): Promise<void> {
    const targets = Object.keys(TARGET_IMAGE_MAP);

    // Build one variant first.
    let firstImageArchitecture = 'x86_64-unknown-linux-musl';
    const firstImage = this.createDockerImage(firstImageArchitecture);

    // Build other variants
    const otherVariants = targets
      .filter(target => target !== firstImageArchitecture)
      .map(target => this.createDockerImage(target));

    // Publish the multi-platform image with all variants.
    //
    // `docker/metadata-action` (the CI caller) outputs FULL references —
    // `joepmeneer/atomic-server:develop` — and prefixing those again produced
    // `joepmeneer/atomic-server:joepmeneer/atomic-server:develop`, which the
    // registry rejects as "invalid reference format". Every develop publish
    // since the tags became a list failed on it. Bare tag names (manual
    // `dagger call create-docker-images --tags latest`) keep working via the
    // prefix.
    for (const tag of tags) {
      const ref = tag.includes('/') ? tag : `joepmeneer/atomic-server:${tag}`;
      await firstImage.publish(ref, {
        platformVariants: otherVariants,
      });
    }
  }
}
