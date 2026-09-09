# Guide for Atomic-Server contributors

First things first: I'm glad you're reading this!
Join our [Discord](https://discord.gg/a72Rv2P) to chat with other people in the Atomic Data community.
If you encounter any issues, add them to the [Github issue tracker](https://github.com/atomicdata-dev/atomic-server/issues).
Same goes for feature requests.
PR's are welcome, too!
Note that opening a PR means agreeing that your code becomes distributed under the MIT license.

If you want to share some thoughts on the Atomic Data _specification_, please [drop an issue in the Atomic Data repo](https://github.com/atomicdata-dev/atomic-server/issues).
Check out the [Roadmap](https://docs.atomicdata.dev/roadmap.html) if you want to learn more about our plans and the history of the project.

## Table of contents

- [Table of contents](#table-of-contents)
- [Translation \& Internationalization](#translation--internationalization)
- [Running \& compiling](#running--compiling)
  - [Running locally (with local development browser)](#running-locally-with-local-development-browser)
  - [IDE setup (VSCode)](#ide-setup-vscode)
  - [Using Dagger](#using-dagger)
  - [Improve local compilation speed](#improve-local-compilation-speed)
  - [Cross compilation](#cross-compilation)
- [Git policy](#git-policy)
  - [Open a PR](#open-a-pr)
  - [Branching](#branching)
  - [Hotfixes](#hotfixes)
- [Testing](#testing)
- [Performance monitoring / benchmarks](#performance-monitoring--benchmarks)
  - [Tracing](#tracing)
    - [Tracing with OpenTelemetry (and SigNoz)](#tracing-with-opentelemetry-and-signoz)
    - [Tracing with Chrome](#tracing-with-chrome)
  - [Criterion benchmarks](#criterion-benchmarks)
  - [Drill](#drill)
- [Responsible disclosure / Coordinated Vulnerability Disclosure](#responsible-disclosure--coordinated-vulnerability-disclosure)
- [Releases, Versioning and Tagging](#releases-versioning-and-tagging)
  - [CI situation](#ci-situation)
  - [Publishing manually - doing the CI's work](#publishing-manually---doing-the-cis-work)
    - [Building and publishing binaries](#building-and-publishing-binaries)
    - [Publishing to Cargo](#publishing-to-cargo)
    - [Publishing to npm](#publishing-to-npm)
    - [Publishing server to Docker](#publishing-server-to-docker)
    - [Deploying to atomicdata.dev](#deploying-to-atomicdatadev)
    - [Publishing atomic-cli to WAPM](#publishing-atomic-cli-to-wapm)

## Translation & Internationalization

AtomicServer supports a small number of languages.
Most of these translations are done by AI and might contain mistakes, if you notice any feel free to [open an issue](https://github.com/atomicdata-dev/atomic-server/issues).

## Running & compiling

TL;DR Clone the repo and run `cargo run` from each folder (e.g. `cli` or `server`).

### Running locally (with local development browser)

- Run `cargo run` to start the server
- Go to `browser`, run `pnpm install` (if you haven't already), and run `pnpm dev` to start the browser
- Visit your `localhost` in your locally running `atomic-data-browser` instance: (e.g. `http://localhost:5173/app/show?subject=http%3A%2F%2Flocalhost`)
- use `cargo watch -- cargo run` to automatically recompile `atomic-server` when you update JS assets in `browser`

### IDE setup (VSCode)

This project is primarily being developed in VSCode.
That doesn't mean that you should, too, but it means you're less likely to run into issues.

- **Tasks**: The `/.vscode` directory contains various `tasks` (open command palette => search "run task")
- **Debugging**: Install the `CodeLLDB` plugin, and press F5 to start debugging. Breakpoints, inspect... The good stuff.
- **Extensions**: That same directory will give a couple of suggestions for extensions to install.

### Using Dagger

Dagger is a tool that's used for building the project.
The `.dagger` directory and the `dagger.json` file contain most of the configuration.
Install the Dagger CLI from [here](https://docs.dagger.io/install/) and run the `dagger` command in the root of the project.
Then you can run the commands from the `.dagger/src/index.ts` file, e.g.
`dagger call build-browser`

If you want to output artifacts (e.g. binaries), use:
`dagger call --interactive release-assets export --pa
th="./build"`

You can pass secrets / ENVS to dagger like so:
`dagger call typedoc-publish --netlify-auth-token="env://NETLIFY_AUTH_TOKEN"`

If Dagger is taking up a lot of storage, run:
`dagger core engine local-cache prune`

Add `-i` to the command to run in interactive mode, add `--output` to save the output to a folder.
Note that the camelCase functions in the `index.ts` file are converted to kebab-case commands in the Dagger API.
Check out the [Dagger docs](https://docs.dagger.io/) for more information.

### Improve local compilation speed

- Use the [`mold`](https://github.com/rui314/mold) linker + create a `.cargo/config.toml` and add `[build] rustflags = ["-C", "link-arg=-fuse-ld=lld"]`
- Note: this is primarily for development on linux systems, as mold for macOS requires a paid license

### Cross compilation

If you want to build `atomic-server` for some other target (e.g. building for linux from macOS), you can use the `cross` crate, which requires `docker`.

```sh
cargo install cross
# make sure docker is running!
cross build --target x86_64-unknown-linux-musl --bin atomic-server --release
```

Check the Dagger index.ts file to see how cross compilation is done in the CI.

## Git policy

One long-lived branch: `develop`. Staging follows it. Production is a stable
`v*` tag, not a branch.

Do not add a `main` that is updated when you tag `develop`. The tag already
*is* the release — a second pointer for the same commit drifts (failed update
job, a direct push, a PR against the GitHub default), and production that
deploys from both `main` and tags can disagree. `master` is not part of this
flow either; it used to own live docs, which now publish from the same stable
tags as production.

### Open a PR

- Make sure your branch is up to date with `develop`.
- Open a PR against `develop`.
- Make sure all relevant tests / lint pass.

### Branching

Create new branches off `develop`. When an issue is ready for PR, open PR against `develop`.

### Hotfixes

When production needs a fix that must not wait for everything already on
`develop`, branch from the tag, tag the fix, merge back:

```sh
git checkout -b hotfix/describe-it v0.40.3
# fix, open a PR, merge
git tag v0.40.4
git push origin v0.40.4
git checkout develop
git merge hotfix/describe-it
```

The new tag is what production deploys. `develop` must get the fix too, or the
next release reintroduces the bug.

## Testing

- We try to test at every level, unit tests, integration tests, e2e tests (playwright).
- When tests fail, first make sure the unit tests are green, then do integration tests, then to e2e.
- If e2e tests fail, try walking through the steps 1 by 1 either with the playwright debugger, or by simply reproducing the steps in your browser of choice.
- Feature-branch CI runs Playwright **light** (`@smoke`). `develop` and `v*` tags run the **full** suite. Opt in to full on a branch with a `full-e2e` PR label, `[full-e2e]` in the commit message, or `workflow_dispatch` `e2e_mode=full`. See `planning/e2e-light-heavy.md`.

```sh
# Make sure nextest is installed
cargo install cargo-nextest
# Runs all tests
# NOTE: run this from the root of the workspace, or else feature flags may be excluded
cargo nextest run
# Run specific test(s)
cargo nextest run test_name_substring
# End-to-end tests, powered by PlayWright and Atomic-Data-Browser
# First, run the server
cargo run
# now, open new terminal window
cd browser && pnpm i && pnpm test-e2e:light   # @smoke, matches feature-branch CI
# full suite (develop / tags / before a release)
pnpm test-e2e
# if things go wrong, debug!
pnpm run test-query {testname}
```

## Performance monitoring / benchmarks

We want to make Atomic Server as fast as possible.
For doing this, we have at least three tools: tracing, criterion and drill.

### Tracing

There are two ways you can use `tracing` to get insights into performance.

#### Tracing with OpenTelemetry (and SigNoz)

- Run the server with `--trace opentelemetry` and add `--log-level trace` to inspect more events
- Sign up for [SigNoz Cloud](https://signoz.io/) (free trial available) or run SigNoz locally with Docker
- Add the following to your `.env`:

```sh
ATOMIC_TRACING=opentelemetry
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
OTEL_EXPORTER_OTLP_ENDPOINT=https://ingest.<region>.signoz.cloud:443
OTEL_EXPORTER_OTLP_HEADERS=signoz-ingestion-key=<your-key>
```

- Visit SigNoz to inspect traces and logs: `https://app.signoz.io/`

For local development without a cloud account, you can run SigNoz locally:

```sh
git clone https://github.com/SigNoz/signoz.git
cd signoz/deploy && docker compose up
```

Then set `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317` (no TLS needed locally).

#### Tracing with Chrome

- Use the `tracing::instrument` macro to make functions traceable. Check out the [tracing](https://docs.rs/tracing/latest/tracing/) docs for more info.
- Run the server with the `--trace chrome` flag.
- Close the server. A `trace-{unix-timestamp}.json` file will be generated in the current directory.
- Open this file with <https://ui.perfetto.dev/> or `chrome://tracing`. This will show you a flamegraph that you can zoom into.

### Criterion benchmarks

We have benchmarks in the `/lib/benchmarks` folder. Make sure there's a benchmark for the thing you're trying to optimize, run the benchmark, then make some changes to the code, then run the benchmark again. You should be able to see the difference in performance.

```sh
# install criterion
cargo install cargo-criterion
# go to atomic-server root folder - don't run benchmarks in `./lib`
cd ..
# run benchmark
cargo criterion
# or if that does not work
cargo bench --all-features
```

### Drill

HTTP-level benchmarking tool.
Sends a ton of requests, measures how long it takes.

```sh
cargo install drill
drill -b benchmark.yml --stats
```

## Responsible disclosure / Coordinated Vulnerability Disclosure

If you encounter serious security risks, please refrain from posting these publicly in the issue tracker.
We could minimize the impact by first patching the issue, publishing the patch, and then (after 30 days) disclose the bug.
So please first send an e-mail to <joep@ontola.io> describing the issue, and then we will work on fixing it as soon as possible.

## AI-assisted contributions

Using AI tools or language models to help write, review, document, test, or understand code is welcome.
Contributors remain responsible for everything they submit, regardless of how it was produced. In particular, AI-generated changes should be reviewed for correctness, security, licensing, maintainability, and unnecessary complexity before submission.
We believe AI can be useful for improving software while also recognizing that increasingly capable AI systems may create serious societal and safety risks. Allowing AI-assisted development here should not be interpreted as an endorsement of unrestricted AI development or deployment.

## Releases, Versioning and Tagging

1. Commit changes
1. Make sure all tests run properly
1. Pick one version for the release, including pre-release suffixes when needed (for example `0.41.0-beta.0`).
1. Bump every version site in lockstep — 15 of them across the Rust crates, the
   `@tomic/*` packages, the starter templates' dependency constraints and
   `desktop/tauri.conf.json`:

   ```sh
   node scripts/bump-version.mjs <old-version> <new-version>
   ```

   Do not do this by hand. The sites do not share a single source of truth, and
   a `grep` for the old version has been observed to silently miss one
   (`browser/lib/package.json`), which would publish a mismatched set to npm.
1. Regenerate lockfiles after version changes:
   - `cargo update --workspace` — **not** `cargo metadata --no-deps`, which
     skips resolution and leaves the workspace members' own versions stale in
     `Cargo.lock`.
   - `cd browser && pnpm install --lockfile-only`
1. Confirm nothing lagged behind:

   ```sh
   node scripts/bump-version.mjs --check <new-version>
   ```
1. Update the `CHANGELOG.md` files (browser and root). Only ever add a section
   for a version you are actually about to tag — a section for a release that
   never shipped is worse than no section, see the `[v0.40.2]` entry for how
   confusing that gets.
1. Tag `v<version>` and push it. CI publishes crates.io, npm, GitHub release
   assets, and (on a stable tag) production. Do not publish crates or npm by
   hand unless CI failed — see [Publishing manually](#publishing-manually---doing-the-cis-work).

The following should be triggered automatically:

- Push the `v*` tag, a Release will automatically be created on Github with the binaries. This will read `CHANGELOG.md`, so make sure to add the changes from there.
- The same tag publishes Rust crates to crates.io and `@tomic/*` packages to npm (`latest` for a stable tag, the pre-release identifier — `beta`, `rc`, … — otherwise).
- The main action required on this repo, is to _update the changelog_ and _tag releases_. The tags trigger the build and publish processes in the CI.

Note:

- We use [semver](https://semver.org/), and are still quite far from 1.0.0.
- The version for `atomic-lib` is the most important, and dictates the versions of `cli` and `server`. When `lib` changes minor version, `cli` and `server` should follow.

### CI/CD pipeline

- Github Action for `push`: builds + tests + docker (using `dagger`, see `.dagger` and the `.github` folders)
- Github Action for `tag`: create release + publish binaries + crates.io + npm
- Docker tags should include immutable release tags such as `0.41.0-beta.0`. `latest` is useful as a convenience tag, but downstream consumers such as Home Assistant add-ons need a changing version tag to reliably detect updates.

### Deployments

Nothing deploys until its pipeline is green.

| Trigger | Deploys to | Docs |
| --- | --- | --- |
| push to `develop` | staging.atomicdata.dev | Netlify preview URL |
| a stable `v*` **tag** | atomicdata.dev | the live docs + typedoc sites |

Staging follows a branch; **production runs a tagged release**. A branch pointer
answers "what was merged most recently", which is not the question you are
asking when production is misbehaving — "which release is this" is, and a tag
answers it. It also means the deployed thing has a name that appears in the
changelog, and that redeploying it later gets you the same bytes. Live docs
follow the same rule, so docs.atomicdata.dev describes the tagged software
rather than whatever last landed on a docs-only branch.

Pre-release tags (`v0.41.0-beta.2` and friends) do **not** deploy the app or
publish live docs. They exist to be published and tested. Put one on production
deliberately via the `workflow_dispatch` if you want it there.

There is no `main` branch, and nothing should refer to one. Do not introduce
one as a fast-forward of the latest tag — see [Git policy](#git-policy).

`release-plz` used to live here, triggered on pushes to `main` — a branch this
repo does not have — so it never ran once, while holding a
`CARGO_REGISTRY_TOKEN`. It is gone rather than repointed. It versions Cargo
crates, and a release here is one version across four Rust crates, twelve
`@tomic/*` packages and `desktop/tauri.conf.json`; it would have bumped one half
and left the other failing `bump-version.mjs --check`. It also generates
changelogs from commit subjects, and these changelogs are written by hand on
purpose.

Both deploy workflows refuse to run against a commit whose pipeline has not
passed. They used to trigger on `push`, which ran the deploy and the pipeline at
the same time, so a red build did not stop the deploy — it just told you
afterwards. Removing that gate is easy to do by accident, so:

- **Staging** waits on `workflow_run`: _Main pipeline: build, lint, test_ must
  **conclude successfully** on `develop`, and only then does the tested commit
  deploy. Moving it back to `push` removes the gate, not just the delay.
- **Production** cannot use `workflow_run` — that event has no tag filter — so
  its `verify` job asks the API whether a successful pipeline exists for the
  tagged commit, and the deploy `needs:` it. `skip_ci_check` exists for
  emergencies and should feel like a decision.

Two consequences worth knowing:

- `workflow_run` checks out the **default branch**, not the commit that passed.
  Staging therefore passes `github.event.workflow_run.head_sha` into
  `deployment.yml`'s required `ref` input; production passes the resolved tag
  SHA. Leaving it out deploys something other than what CI tested, silently.
- Docs publishing is opt-in per ref. `dagger call ci` takes `--publish-docs`,
  and `main-ci.yml` passes it only for a stable `v*` tag (no hyphen in the tag
  name). Without it Netlify gets a preview deploy. This used to be
  unconditional `--prod`, which meant pushing any feature branch republished
  the public documentation, and later `master`-only, which left live docs on a
  branch that was not production.
- Playwright is `--playwright-mode light` on feature-branch pushes (`@smoke` only)
  and `full` on `develop` and `v*` tags. `dagger call ci` defaults to `full`
  so omitting the flag cannot shrink a release gate. Opt in from a branch
  with a `full-e2e` PR label, `[full-e2e]` in the commit message, or
  `workflow_dispatch` `e2e_mode=full`. (Do not name the Dagger flag
  `--e2e-mode`: the CLI camelCases it to `e2EMode` and the call fails.)

Every deploy then has to prove itself: the job polls `/server` on the target
until it answers `200` (with enough patience for a store migration). A deploy
that "succeeds" while the process crash-loops is otherwise invisible — that
happened, and staging stayed dead for over an hour behind a green checkmark.

If the health check fails, the job restores the previous binary automatically.
Each deploy leaves a timestamped copy, so the last one that actually served
traffic is still on disk. The rollback deliberately **does not touch the
store**: if the new binary migrated it on boot, an older binary may not read it
back, and a rollback that quietly mangles data is worse than an outage. Use the
export taken during the deploy, and expect to think.

To deploy a specific commit — a rollback, or a fix that cannot wait for a full
pipeline — use the `workflow_dispatch` on either deploy workflow and give it a
ref. Production dispatch has no default on purpose: type the tag (or SHA) you
mean; the old default was `master`. To require human approval for production,
add reviewers to the `production` environment in the repository settings; the
environment is already declared, so no workflow change is needed.

### Publishing manually - doing the CI's work

If the CI scripts for some reason do not do their job (building releases, docker file, publishing to cargo or npm), you can follow these instructions:

#### Building and publishing binaries

1. `cargo build --release`
1. Create a release on github, add the binaries

#### Publishing to Cargo

1. Update the versions in cargo.toml files using Semantic Versioning.
1. run `cargo publish` in `lib`, than you can run the same in `cli` and `server`

OR

1. Install `cargo install cargo-release` and run `cargo release patch`

#### Publishing to npm

CI does this on a `v*` tag (`release.yml` `npm` job). Auth is the `NPM_TOKEN`
repo secret (granular automation token, write to `@tomic`) or npm Trusted
Publishing pointed at this workflow. Pre-releases go to the `beta` / `rc`
dist-tag, not `latest`.

1. `cd browser && pnpm install --frozen-lockfile`
1. `pnpm --filter @tomic/lib --filter @tomic/react --filter @tomic/cli --filter @tomic/svelte --filter @tomic/create-template --filter @tomic/plugin --filter @tomic/edit-mode run build`
1. `pnpm publish -r --no-git-checks --ignore-scripts --access public --tag <latest|beta>`
   - `--ignore-scripts` skips `prepublishOnly`. Build first (step 2);
     `@tomic/lib`'s `attw` currently crashes and would fail the publish.
   - DONT run `pnpm npm publish`: it skips the `workspace:*` rewrite and
     publishes a package that cannot resolve `@tomic/lib`.

#### Publishing server to Docker

Docker publishing is handled by the Dagger pipeline. Prefer publishing immutable version tags and, when appropriate, `latest`.

1. build and publish: `dagger call create-docker-images --tags 0.41.0-beta.0 --tags latest`
1. run, make sure it works: `docker run -p 9883:80 ghcr.io/ontola/atomic-server:0.41.0-beta.0`

For a single local ARM64 image, use `dagger call create-docker-image --target aarch64-unknown-linux-musl export --path /tmp/atomic-server.tar`, then load and tag it with Docker.

#### Deploying to atomicdata.dev

Push a stable `v*` tag. That is what production follows. To deploy a tag (or
commit) by hand, run the
[`deploy_production` GitHub Action](https://github.com/atomicdata-dev/atomic-server/actions/workflows/deploy_production.yml)
and pass that ref.

Or do it manually:

1. `cd server`
1. `cargo build --release --target x86_64-unknown-linux-musl --bin atomic-server` (if it fails, use cross, see above)
1. `scp ../target/x86_64-unknown-linux-gnu/release/atomic-server atomic:~/atomic/server/atomic-server-v0.{version}`
1. `ssh atomic` (@joepio manages server)
1. `service atomic restart`

```sh
# logs
journalctl -u atomic.service
# logs, since one hour, follow
journalctl -u atomic.service --since "1 hour ago" -f
```

#### Publishing atomic-cli to WAPM

1. Install `wasmer` and `cargo-wasi`.
1. `cd cli`
1. run `cargo wasi build --release --no-default-features` (note: this fails, as ring does not compile to WASI [at this moment](https://github.com/briansmith/ring/issues/1043))
1. `wapm publish`
