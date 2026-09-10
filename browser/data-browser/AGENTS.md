# Data Browser

## Sync & onboarding — read first

The Flutter canvas app (`flutter/lib/atomic/`) is a client of the same system,
used by the same person. Before changing anything about signing in, servers,
pairing or sync, read
[`../../planning/sync-onboarding-ux.md`](../../planning/sync-onboarding-ux.md):
it holds the shared vocabulary, the rules of what can actually reach what (rights
decide, on every transport — not whose device it is), every account/device path, and
the map of which file here twins which file in the Flutter app.

Change a sync screen here → change its twin there, and update that doc.

## Editing UI

IMPORTANT!: When working on the data-browser, determine if you need to change or add UI, if so, read `./UI_COMPONENTS.md` for a list of existing reusable components.
Prefer the existing reusable layout, resource view, overlay, button, loading, and accessibility components listed there before building new components from scratch.

## Tech Stack

This project uses Pnpm, Vite, React, TypeScript, Styled Components, and the Atomic Data ecosystem.

### React Compiler

We are using the React Compiler so manual memoization is often not needed. Make sure to follow the rules of React Hooks so the compiler can do its job.
The compiler currently has some trouble compiling components that contain try/catch blocks with complex logic like if statements or async code.
Additionally the use of `finally` is not yet supported inside components.
Those show up as Vite warnings from `oxc-transform-react` and as Oxlint `react/*` compiler rules; the component still runs, just without auto-memoization.
styled-components `displayName` is added by Oxc's built-in plugin on Vite's oxc pass — there is no Babel in this package.

After editing a React component or hook, check its compiler diagnostics with:

```sh
# From the repository root; accepts multiple files or absolute paths.
node browser/data-browser/scripts/check-react-compiler.mjs browser/data-browser/src/chunks/AI/useAtomicTools.ts
# From browser/data-browser:
pnpm check:react-compiler src/chunks/AI/useAtomicTools.ts
```

The check uses the app's installed Oxc compiler and exits nonzero on diagnostics
(including optimization bailouts). It reports whether memoization was emitted
for the file, not whether every function was memoized. A clean transform without
memoization is explicitly reported; check for opt-outs or ineligible functions.
IDE extensions using Babel React Compiler can report different results. Run
`pnpm typecheck` separately for TypeScript errors.

Diagnostics default to `file:line:column — message`; add `--verbose` for code
frames. The repository's `.codex/hooks.json` also runs this compiler after
`apply_patch` and Bash tools. It checks staged, unstaged and untracked JS/TS in
`browser/data-browser/src`, excluding tests, declaration files and workers.
Content hashes are cached per checkout and Codex session in the OS temporary
directory. Successful and unchanged files produce no hook output; failures are
advisory context, not a blocking gate. Existing issues may be reported on the
first check; fix regressions relevant to the current task, not unrelated bailouts.

New or changed Codex hooks require a trust review: open `/hooks` in the Codex CLI
for this repository and review the React Compiler hook. Until trusted, use the
manual command above. Hook feedback does not replace typecheck or runtime tests.

Claude Code uses the same checker through `.claude/settings.json`, after `Edit`,
`Write` and successful `Bash` calls. It has the same compact, cached, advisory
behavior. Check `/hooks` in Claude Code to inspect the project hook. Both clients
key their cache by checkout and session ID; personal Claude settings and worktrees
remain git-ignored.

## Localization

We are using Wuchale for localization.
It handles text extraction and translation automatically.
Use ignore comments (`/* @wc-ignore */` or `// @wc-ignore-file`) to exclude certain strings or files from being translated (For example agent system prompts).
All strings not in any function or JSX scope are automatically ignored. Strings in functions or element attributes are ignored when they do not start with a capital letter.

## Verify your edits

After your done makeing your changes. Use `pnpm typecheck` to verify there are no type errors.
