import { expect, it } from "vitest";
import { run } from "./plugin";
const config = {
  platform: "github-issues",
  destinations: {
    issue: { table: "https://example.com/table", rowClass: "https://example.com/issue" },
  },
  properties: { title: "https://example.com/title", number: "https://example.com/number" },
  records: [
    {
      resource: "issue",
      namespace: "ontola/atomic-server",
      id: "1",
      name: "A real issue",
      values: { title: "A real issue", number: 42 },
    },
  ],
};
it("maps fetched records into typed proposals with scoped identity", () => {
  const result = run({ config, query: () => [], read: () => ({}) });
  expect(result.intents).toHaveLength(1);
  expect(result.intents[0]).toMatchObject({
    op: "create",
    parent: config.destinations.issue.table,
    isA: [config.destinations.issue.rowClass],
    set: { [config.properties.title]: "A real issue", [config.properties.number]: 42 },
  });
});
it("rejects absent fetched records and missing identities", () => {
  expect(() =>
    run({ config: { ...config, records: undefined }, query: () => [], read: () => ({}) }),
  ).toThrow();
  expect(() =>
    run({
      config: { ...config, records: [{ ...config.records[0], id: "" }] },
      query: () => [],
      read: () => ({}),
    }),
  ).toThrow(/identity/);
});
it("repeated imports preserve local edits and propose no duplicates", () => {
  const first = run({ config, query: () => [], read: () => ({}) }).intents[0];
  if (first.op !== "create") throw new Error("Expected create");
  const saved: Record<string, unknown> = {
    ...first.set,
    "https://atomicdata.dev/properties/parent": config.destinations.issue.table,
    "https://atomicdata.dev/properties/isA": [config.destinations.issue.rowClass],
  };
  const host = {
    config,
    query: (p: string, v: string) => (saved[p] === v ? ["https://example.com/row"] : []),
    read: () => saved,
  };
  expect(run(host).intents).toHaveLength(0);
  saved[config.properties.title] = "My local title";
  expect(run(host).intents).toHaveLength(0);
});
it("refuses duplicate source identities", () => {
  expect(() =>
    run({
      config: { ...config, records: [config.records[0], config.records[0]] },
      query: () => [],
      read: () => ({}),
    }),
  ).toThrow(/duplicate/);
});
