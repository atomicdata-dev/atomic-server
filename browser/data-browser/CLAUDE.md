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

## Localization

We are using Wuchale for localization.
It handles text extraction and translation automatically.
Use ignore comments (`/* @wc-ignore */` or `// @wc-ignore-file`) to exclude certain strings or files from being translated (For example agent system prompts).
All strings not in any function or JSX scope are automatically ignored. Strings in functions or element attributes are ignored when they do not start with a capital letter.

## Verify your edits

After your done makeing your changes. Use `pnpm typecheck` to verify there are no type errors.
