# Contribute

Issues and PR's are welcome!
Note that your code changes will be distributed under the MIT license of this repo.
Check out the [Roadmap](https://docs.atomicdata.dev/roadmap.html) if you want to learn more about our plans and the history of the project.
Talk with other devs on our [Discord][discord-url]!

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P

## Publishing

CI publishes `@tomic/*` to npm when a `v*` tag is pushed (`release.yml` `npm`
job). Use the steps below only when that job failed or you are publishing
from a machine that is not CI.

- `pnpm lint-fix`
- commit any changes (if they are there)
- `pnpm build` to build typescript files (don't skip this!)
- make sure `atomic-server` is running on `localhost`.
- `pnpm test`
- `pnpm test-e2e`
- Bump versions with `node scripts/bump-version.mjs` from the repo root — do
  not edit `package.json` files by hand. Versions must match the Rust release,
  including beta versions such as `0.41.0-beta.0`.
- Update starter template dependencies that point to `@tomic/*` (the bump
  script does this).
- Run `pnpm install --lockfile-only` from `/browser` after version changes.
- Check the [changelog](changelog.md), make sure the headers are correct
- Now do the rust libraries
- Commit any changes, name it `vX.XX.XX`, tag and push. CI publishes to npm.
- If you must publish by hand: `pnpm publish -r --no-git-checks --access public --tag <latest|beta>`
  - Pre-releases must use `--tag beta` (or `rc`, …). The default is `latest`,
    which would replace the stable install.
  - DONT run `pnpm npm publish`, as it will not resolve workspace dependencies correctly.

## Understanding vite and pnpm workspaces

This monorepo is orchestrated with pnpm workspaces.
pnpm workspaces are used to share dependencies.

Vite hosts the data-browser and targets `.ts` files which enables hot reload / hot module replacement, which is great for developing the data browser and the libraries at the same time.

## Iterative builds

If you're editing `@tomic/lib` or `@tomic/react`, you need to re-build the library, as `atomic-data-browser` imports the `.js` files.
You can auto re-build using the `watch` commands in `@tomic/lib` and `@tomic/react`.
If you run `pnpm start` from the root, these will be run automatically.

## Localization

Atomic Data Browser uses [Wuchale](https://wuchale.dev/) for localization.
When adding new text to the app wuchale will automatically extract it and add it to the locale files (When running the vite dev server).
Make sure you provide translations for the any new text you add.
To help with this you can provide a Google Gemini API key, Wuchale will then use this to generate translations for you automatically.
To do so export the key in your terminal or use something like direnv to set the key: `export GEMINI_API_KEY=your_api_key`
More info: [How to use Gemini live translation](https://wuchale.dev/guides/gemini/)
