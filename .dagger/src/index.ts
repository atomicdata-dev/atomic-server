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
} from '@dagger.io/dagger';

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

const NODE_IMAGE = 'node:22';
const RUST_IMAGE = 'rust:bookworm';

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
const PLAYWRIGHT_PACKAGE_VERSION = '1.60.0';
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
    `pnpm exec playwright test --config=./playwright.config.ts${grepFlag} --shard=${shardIndex}/${shardCount} 2>&1 | tee /test-output.log; ` +
    'echo ${PIPESTATUS[0]} > /test-exit-code; exit 0'
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
  // 4 shards × 2 workers ≈ 8 browsers. `ci()` runs endToEnd concurrently with
  // clippy/nextest/flutter/vitest, so the box carries those browsers AND their
  // four debug atomic-servers AND cargoBuildJobs=8 AND a 6-wide nextest at the
  // same time. At 3 workers that was 12 browsers on 12 cores and the suite
  // failed accordingly — including a chromium killed outright ("Target page,
  // context or browser has been closed"), which is starvation, not a race.
  // Raise this only alongside the cargo/nextest widths it shares the host with.
  mancave: {
    e2eShardCount: 4,
    e2ePlaywrightWorkers: '2',
    // Back to the suite's own documented default (playwright.config.ts): three
    // attempts catch a genuinely flaky path while a real regression still
    // fails all three. This branch dropped it to 1 for runtime, and that trade
    // stopped paying: what remains red here rotates run to run — a click that
    // did not land, a menu that did not open — which is the shape of a
    // contended host, not of a broken test. Mitigation, not a fix; the fix is
    // headroom, and `ci()` still runs these browsers alongside clippy,
    // nextest, flutter and two vitest suites.
    e2ePlaywrightRetries: '2',
    nextestTestThreads: '6',
    nextestRetries: '1',
    nextestBuildJobs: '4',
    cargoBuildJobs: '8',
  },
  hosted: {
    e2eShardCount: 2,
    e2ePlaywrightWorkers: '1',
    e2ePlaywrightRetries: '2',
    nextestTestThreads: '2',
    nextestRetries: '2',
    nextestBuildJobs: '2',
    cargoBuildJobs: '2',
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
  ) {
    this.source = source;
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
            'cargo install mdbook mdbook-linkcheck --quiet && ' +
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
     * `mancave` = hot parallelism for the 12c/64GB self-hosted runner.
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
  ): Promise<string> {
    this.hostProfile = resolveHostProfile(hostProfile);
    this.hostKnobs = HOST_PROFILES[this.hostProfile];

    // Fail fast on cheap static checks. A store.ts oxfmt miss used to burn
    // ~20+ minutes of rust/e2e compile before jsLint surfaced it.
    await Promise.all([this.jsLint(), this.rustFmt()]);

    // Rust clippy/test still share the `rust-target` cache mount — keep
    // them serialized (parallel cargo contended the target lock for
    // ~16 minutes and exited 101). Everything else is independent.
    await Promise.all([
      this.docsPublish(netlifyAuthToken, publishDocs),
      this.typedocPublish(netlifyAuthToken, publishDocs),
      this.endToEnd(netlifyAuthToken, playwrightMode),
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
    const depsContainer = this.jsBuild();

    return depsContainer
      .withWorkdir('/app')
      .withExec(['pnpm', 'run', 'lint'])
      .stdout();
  }

  @func()
  async jsTest(): Promise<string> {
    const depsContainer = this.jsBuild();

    return (
      depsContainer
        .withWorkdir('/app')
        .withExec(['pnpm', 'run', 'test'])
        .withExec([
          'node',
          '--test',
          'data-browser/scripts/integration-mcp.test.mjs',
        ])
        // Provider packages stay outside core/browser bundles, but their fixture
        // tests run in the same JS gate. Mirror the repo layout for SDK imports.
        .withDirectory('/integrations', this.source.directory('integrations'))
        .withExec(['ln', '-s', '/app', '/browser'])
        .withWorkdir('/')
        .withExec(['node', '--test', '/integrations/tooling/certify.test.mjs'])
        .withExec([
          'node',
          '/integrations/tooling/certify.mjs',
          '--layer',
          'js',
          '--output',
          '/integration-certification',
        ])
        .stdout()
    );
  }

  /** Export offline provider evidence; live provider writes are never run here. */
  @func()
  integrationCertificationReport(): Directory {
    return this.jsBuild()
      .withDirectory('/integrations', this.source.directory('integrations'))
      .withExec(['ln', '-s', '/app', '/browser'])
      .withWorkdir('/')
      .withExec(['node', '--test', '/integrations/tooling/certify.test.mjs'])
      .withExec([
        'node',
        '/integrations/tooling/certify.mjs',
        '--layer',
        'js',
        '--output',
        '/integration-certification',
      ])
      .directory('/integration-certification');
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
    const flutterCargoCache = dag.cacheVolume('flutter-cargo');
    const flutterRustTarget = dag.cacheVolume('flutter-plugin-rust-target');
    const flutterPubCache = dag.cacheVolume('flutter-pub-cache');
    const flutterRustup = dag.cacheVolume('flutter-rustup');
    const pathPrefix = 'export PATH="$HOME/.cargo/bin:$PATH"';

    return (
      dag
        .container()
        .from(FLUTTER_IMAGE)
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
        .withDirectory('/workspace/lib', this.source.directory('lib'))
        .withDirectory('/workspace/flutter', this.source.directory('flutter'))
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
        // Cache `cargo install`-built binaries (wasm-pack here). Without
        // this, each CI run recompiled wasm-pack from source (~2 min).
        // Routed through `CARGO_INSTALL_ROOT` to a non-default path so
        // the cache mount can't hide the rust image's preinstalled
        // \`cargo\`/\`rustc\` at \`/usr/local/cargo/bin\`. Adding the
        // install root's \`bin\` to \`PATH\` makes \`wasm-pack\` resolvable.
        // \`cargo install\` no-ops when the latest version is already
        // present.
        .withMountedCache('/opt/cargo-bin', dag.cacheVolume('cargo-bin'), {
          // Shared so wasm-pack and mdbook installs can proceed in parallel.
          sharing: CacheSharingMode.Shared,
        })
        .withEnvVariable('CARGO_INSTALL_ROOT', '/opt/cargo-bin')
        .withEnvVariable(
          'PATH',
          '/opt/cargo-bin/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        )
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
        .withDirectory(
          '/code/integrations/localthought/syncables',
          this.source.directory('integrations/localthought/syncables'),
        )
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
          dag.cacheVolume('rust-wasm-target-v3'),
        )
        .withExec(TOUCH_WORKSPACE_SOURCES)
        .withWorkdir('/code/wasm')
        // Install + build in a single exec so the install is part of the
        // build step's own cache key. Splitting them lets dagger cache the
        // `cargo install` step as "already ran" while the mounted
        // `cargo-bin` cache volume can be cleared by the engine (e.g. after
        // a restart with `Locked` sharing), leaving wasm-pack missing from
        // PATH on replay ("executable file not found in $PATH"). Bundling
        // makes any cache hit imply the binary is present too; `cargo
        // install` no-ops when the binary is current.
        //
        // `CARGO_ENCODED_RUSTFLAGS` is exported INLINE so it only applies
        // to the wasm-pack build. Setting it at container scope leaks into
        // `cargo install wasm-pack` (which compiles wasm-pack for the host
        // triple, not wasm32) and trips getrandom's
        //   "wasm_js backend can be enabled only for OS-less WASM targets!"
        // compile_error. The `\x1f` is the encoded-rustflags arg separator.
        .withExec([
          'sh',
          '-c',
          'cargo install wasm-pack --quiet && ' +
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
          '/code/integrations/localthought/syncables',
          this.source.directory('integrations/localthought/syncables'),
        )
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
          dag.cacheVolume('rust-slim-target-v3'),
        )
        .withExec(TOUCH_WORKSPACE_SOURCES)
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
      .withExec(['npm', 'install', '--global', 'corepack@latest'])
      .withExec(['corepack', 'enable'])
      .withExec(['corepack', 'prepare', 'pnpm@latest-10', '--activate'])
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
      .withExec([
        'sh',
        '-c',
        'yes | pnpm install --frozen-lockfile --shamefully-hoist',
      ]);

    // Drop in @tomic/lib source. Other packages are unused by the
    // integration tests, so we don't bother mounting them.
    const withSource = installed.withDirectory(
      '/repo/browser/lib',
      browser.directory('lib'),
    );

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

  /** Extracts the unique deploy URL from netlify output */
  private extractDeployUrl(netlifyOutput: string): string {
    const match = netlifyOutput.match(/https:\/\/[a-f0-9]+--.+\.netlify\.app/);

    return match ? match[0] : 'Deploy URL not found';
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
        .withExec([
          'sh',
          '-c',
          'cargo install mdbook mdbook-linkcheck --quiet && mdbook build',
        ])
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

  @func()
  private jsBuild(e2e: boolean = false): Container {
    const browser = this.source.directory('browser');
    // Create a container with PNPM installed
    const pnpmContainer = dag
      .container()
      .from(NODE_IMAGE)
      .withExec(['npm', 'install', '--global', 'corepack@latest'])
      .withExec(['corepack', 'enable'])
      .withExec(['corepack', 'prepare', 'pnpm@latest-10', '--activate'])
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
      // Cache pnpm's content-addressable store across CI runs. Without
      // this, every push re-downloaded all node_modules from the
      // registry — adding ~30-60s per run depending on registry latency.
      // The store is mounted at a workspace-local path and pnpm is
      // pointed at it explicitly; the default
      // `~/.local/share/pnpm/store` wouldn't be picked up by a mount at
      // `/app/.pnpm-store` without the config command.
      .withMountedCache('/app/.pnpm-store', dag.cacheVolume('pnpm-store'))
      .withExec(['pnpm', 'config', 'set', 'store-dir', '/app/.pnpm-store'])
      .withExec([
        'sh',
        '-c',
        'yes | pnpm install --frozen-lockfile --shamefully-hoist',
      ]);

    // data-browser bootstrap JSON lives in repo-root lib/defaults. Vite resolves ../../../lib
    // from data-browser/src to filesystem /lib if /app is only browser — do not mount there
    // (it overwrites OS /lib). Mount alongside browser and resolve via alias in vite.config.
    const sourceContainer = workspaceContainer
      .withDirectory('/app', browser)
      // Integration sources live at the repository root. The browser mounts at
      // /app, and its raw imports resolve these paths from /integrations.
      .withDirectory('/integrations', this.source.directory('integrations'))
      // Each integrations/*/tsconfig.json extends the repo-root-relative
      // `../../browser/tsconfig.build.json`. Same fix jsTest()/
      // integrationCertificationReport() already use for this: alias /browser
      // to the /app mount so those relative paths resolve.
      .withExec(['ln', '-s', '/app', '/browser'])
      .withDirectory('/app/lib-defaults', this.source.directory('lib/defaults'))
      // Provide the prebuilt WASM artifacts so data-browser's `build` can skip
      // wasm-pack when `SKIP_WASM_BUILD=1` (`wasm-pack` isn't available in this
      // Node-only container, and mounting the Rust toolchain just for this would
      // bloat the JS image significantly).
      .withDirectory('/app/data-browser/public/wasm', this.wasmBuild())
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
      // data-browser/src/helpers/pairing.test.ts reads a repo-root testdata
      // fixture the same way (`../../../../testdata/pairing-request.json`
      // from /app/data-browser/src/helpers). `/testdata` isn't an OS path
      // (unlike `/lib` above), so mount the whole directory rather than
      // picking files one at a time — lib/plugin-plan.fixtures.test.ts also
      // needs to `readdirSync` the `plugin-plans/` subdirectory, which a
      // single-file mount can't provide.
      .withDirectory('/testdata', this.source.directory('testdata'))
      // lib/src/task-schema.test.ts reads repo-root `lib/defaults/tasks.json`
      // the same plain-`readFileSync` way as genesis_test_vectors.json above
      // (`../../../lib/defaults/tasks.json` from /app/lib/src). Mount just
      // this file, under the same /lib collision caution as above.
      .withFile(
        '/lib/defaults/tasks.json',
        this.source.file('lib/defaults/tasks.json'),
      );

    // Build all packages since they may depend on each other's built artifacts
    let buildContainer = sourceContainer.withEnvVariable(
      'SKIP_WASM_BUILD',
      '1',
    );

    if (e2e) {
      // Surfaces /app/dev-drive and /app/prunetests in the production
      // build the e2e tests run against. See `devRoutesEnabled()` in
      // data-browser/src/config.ts.
      buildContainer = buildContainer
        .withEnvVariable('VITE_E2E', 'true')
        .withEnvVariable(
          'VITE_INTEGRATION_PROXY_URL',
          'http://127.0.0.1:19090',
        );
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
        '/code/integrations/localthought/syncables',
        source.directory('integrations/localthought/syncables'),
      )
      .withDirectory(
        '/code/plugin-examples',
        source.directory('plugin-examples'),
      )
      .withDirectory('/code/atomic-plugin', source.directory('atomic-plugin'))
      .withDirectory('/code/tools', source.directory('tools'))
      // v3 -> v4: `atomic-server`'s build.rs only declares
      // `rerun-if-changed` on `plugin-runtime/{src,wit}` and
      // `ATOMICSERVER_SKIP_PLUGIN_RUNTIME` — it has no way to know "the
      // wasm32-wasip2 target just became installed". Adding the `rustup
      // target add` step above changed the container, but every prior CI
      // run had already fingerprinted build.rs's output (an empty embedded
      // runtime, from before that target existed) into this cache volume,
      // so cargo kept trusting the stale fingerprint and never re-ran
      // build_plugin_runtime() to notice the target was now there. Bumping
      // the volume forces one full rebuild that actually re-evaluates it.
      .withMountedCache('/code/target', dag.cacheVolume('rust-target-v4'))
      .withExec(TOUCH_WORKSPACE_SOURCES)
      .withWorkdir('/code')
      .withExec(['cargo', 'fetch']);

    const browserDir = this.jsBuild(e2e).directory('/app/data-browser/dist');
    const containerWithAssets = sourceContainer.withDirectory(
      '/code/server/assets_tmp',
      browserDir,
    );

    // Scope the build to `atomic-server` so cargo doesn't try to build
    // workspace siblings like the wasm cdylib plugin examples — which
    // can't be compiled for the host musl target.
    // `e2e` selects the `e2e` cargo profile (see the workspace Cargo.toml):
    // the debug build's behaviour — assertions and overflow checks included —
    // at an optimisation level where commit round-trips stop dominating, and
    // cheap enough to compile that Playwright is not left waiting on LTO.
    const buildArgs = e2e
      ? ['cargo', 'build', '--profile', 'e2e', '-p', 'atomic-server']
      : release
        ? ['cargo', 'build', '--release', '-p', 'atomic-server']
        : ['cargo', 'build', '-p', 'atomic-server'];

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
          '/code/integrations/localthought/syncables',
          source.directory('integrations/localthought/syncables'),
        )
        .withDirectory(
          '/code/plugin-examples',
          source.directory('plugin-examples'),
        )
        .withDirectory('/code/atomic-plugin', source.directory('atomic-plugin'))
        .withDirectory('/code/tools', source.directory('tools'))
        .withMountedCache(
          '/code/target',
          dag.cacheVolume('rust-checks-target-v3'),
        )
        .withExec(TOUCH_WORKSPACE_SOURCES)
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
        .withExec(['cargo', 'fetch'])
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
            'curl -LsSf https://get.nexte.st/latest/linux-musl | tar zxf - -C "$BIN_DIR"; fi && ' +
            'cargo nextest run --workspace --exclude atomic-server-tauri ' +
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
  atomicService(@argument() e2e: boolean = false): Service {
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

    let service = dag
      .container()
      .from(e2e ? 'node:22-alpine' : 'alpine:latest')
      .withFile('/atomic-server-bin', atomicServerBinary, {
        permissions: 0o755,
      })
      .withEnvVariable('ATOMIC_DOMAIN', ATOMIC_DOMAIN)
      // First-run flag — sets up the bootstrap agent + public drive +
      // /app/dev-drive endpoint that the e2e tests' `beforeEach` relies on.
      // Without this, every test's `before()` hook times out fetching it.
      .withEnvVariable('ATOMIC_INITIALIZE', 'true')
      .withExposedPort(9883)
      .withEntrypoint(['/atomic-server-bin']);
    if (e2e)
      service = service
        .withDirectory(
          '/mock-proxy',
          this.source.directory('integrations/localthought'),
        )
        .withEnvVariable(
          'ATOMIC_INTEGRATION_PROXY_URL',
          'http://127.0.0.1:19090',
        )
        .withEnvVariable('TENANT_SECRET', 'bW9jay10ZW5hbnQ.mock-signature')
        .withEnvVariable(
          'ATOMIC_INTEGRATION_FRONTEND_ORIGIN',
          'http://atomic.localhost:9883',
        )
        .withEnvVariable('MOCK_FRONTEND_ORIGIN', 'http://atomic.localhost:9883')
        .withEnvVariable('MOCK_PROXY_HOST', '0.0.0.0')
        .withExposedPort(19090)
        .withEntrypoint([
          'sh',
          '-c',
          'node /mock-proxy/mock-proxy.mjs & exec /atomic-server-bin',
        ]);
    return service.asService().withHostname(ATOMIC_DOMAIN);
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
        '/root/.local/share/pnpm:/opt/npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      )
      .withExec([
        '/bin/sh',
        '-c',
        'curl -fsSL https://get.pnpm.io/install.sh | env PNPM_VERSION=10.15.1 ENV="$HOME/.shrc" SHELL="$(which sh)" sh - && ' +
          'export PATH=/root/.local/share/pnpm:/opt/npm-global/bin:$PATH && ' +
          '/bin/apt update && /bin/apt install -y zip && ' +
          'if [ ! -x /opt/npm-global/bin/netlify ]; then npm install -g netlify-cli --quiet; fi && netlify --version',
      ]);

    // Bug fix (2026-07-02): mount the full pnpm workspace before
    // `pnpm install` — see git history for ERR_PNPM_WORKSPACE_PKG_NOT_FOUND.
    return (
      playwrightContainer
        .withEnvVariable('CI', 'true')
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
        .withServiceBinding('atomic', this.atomicService(true))
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
        .withEnvVariable('ATOMIC_MOCK_INTEGRATION_PROXY', '1')
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
    /**
     * Optional Playwright regular expression for one focused browser journey.
     * A focused run stays on one server/shard, so an exact test does not run
     * alongside unrelated E2E failures.
     */
    @argument() playwrightGrep: string = '',
  ): Promise<string> {
    // Shards × own atomic-server. Count comes from `--host-profile`
    // (Mancave hot / hosted conservative) plus `--playwright-mode` (light uses
    // fewer shards). Dagger dedupes the shared debug `rustBuild(e2e)` /
    // base-container graph.
    this.e2eRun = e2eRunKnobs(this.hostProfile, resolveE2eMode(playwrightMode));
    if (playwrightGrep)
      this.e2eRun = {
        ...this.e2eRun,
        shardCount: 1,
        grep: playwrightGrep,
      };
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
      throw new Error(
        `E2E tests failed on ${failed.length}/${shardCount} shard(s).\n` +
          `Reports:\n${reportUrls.join('\n')}\n\n${tails}` +
          (contexts ? `\n\n${contexts}` : ''),
      );
    }

    return reportUrls.join('\n') || 'e2e ok (no report URL)';
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
