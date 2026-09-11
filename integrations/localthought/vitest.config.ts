export default {
  // Keep module IDs independent of the caller, especially a container cwd of /.
  root: new URL(".", import.meta.url).pathname,
  resolve: {
    alias: {
      vitest: new URL("../../browser/node_modules/vitest/dist/index.js", import.meta.url).pathname,
      devonian: new URL(
        "../../browser/data-browser/node_modules/devonian",
        import.meta.url,
      ).pathname,
    },
  },
  test: { include: ["*.test.ts"] },
};
