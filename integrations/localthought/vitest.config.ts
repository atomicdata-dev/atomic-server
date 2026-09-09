export default {
  resolve: {
    alias: {
      vitest: new URL("../../browser/node_modules/vitest/dist/index.js", import.meta.url).pathname,
    },
  },
  test: { include: ["integrations/localthought/*.test.ts"] },
};
