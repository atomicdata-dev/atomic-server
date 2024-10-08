# Contribute

Issues and PR's are welcome!
Note that your code changes will be distributed under the MIT license of this repo.
Check out the [Roadmap](https://docs.atomicdata.dev/roadmap.html) if you want to learn more about our plans and the history of the project.
Talk with other devs on our [Discord][discord-url]!

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P

## Publishing

- `pnpm lint-fix`
- commit any changes (if they are there)
- `pnpm build` to build typescript files (don't skip this!)
- make sure `atomic-server` is running on `localhost`.
- `pnpm test`
- `pnpm test-e2e`
- Update the `package.json` files for `lib`, `react`, and `data-browser` with a new version number. Match the version number with `atomic-data-rust`
- Check the [changelog](changelog.md), make sure the headers are correct
- Now do the rust libraries
- Commit any changes, name it `vX.XX.XX`
- `pnpm publish -r`
  - Choose a new version. Versions should match `atomic-data-rs`.
  - This updates the `package.json` files, creates a commit, tags it, pushes it to github, and publishes the builds to npm.
  - If this fails, try `pnpm version patch` and `pnpm publish`
  - DONT run `pnpm npm publish`, as it will not resolve workspace dependencies correctly.

## Understanding vite and pnpm workspaces

This monorepo is orchestrated with pnpm workspaces.
pnpm workspaces are used to share dependencies.

Vite hosts the data-browser and targets `.ts` files which enables hot reload / hot module replacement, which is great for developing the data browser and the libraries at the same time.

## Iterative builds

If you're editing `@tomic/lib` or `@tomic/react`, you need to re-build the library, as `atomic-data-browser` imports the `.js` files.
You can auto re-build using the `watch` commands in `@tomic/lib` and `@tomic/react`.
If you run `pnpm start` from the root, these will be run automatically.
Note that you may need to refresh your screen manually to show updates from these libraries.

There are two possible solutions for improving this workflow:

- In `package.json` of the libraries, set the `main` to `src/index.ts` (the typescript file). However, make sure to _not_ publish this to npm, as many clients will fail.
- Properly set up aliases with vite. I've tried this before, but failed.
