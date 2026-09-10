import { expect, it } from "vitest";
import {
  configuredProxy,
  proxySettingKey,
  readSavedConnection,
  savedConnectionKey,
  saveProxy,
} from "./settings";
function storage() {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => {
      values.set(key, value);
    },
    removeItem: (key: string) => {
      values.delete(key);
    },
  };
}
it("persists a runtime proxy override and resets to the deployment default", () => {
  const s = storage();
  expect(configuredProxy(s, "https://deployment.example")).toBe("https://deployment.example");
  saveProxy(s, " https://custom.example/ ");
  expect(configuredProxy(s)).toBe("https://custom.example");
  saveProxy(s, "");
  expect(configuredProxy(s, "https://deployment.example")).toBe("https://deployment.example");
});
it("rejects invalid URLs without overwriting the working setting", () => {
  const s = storage();
  saveProxy(s, "http://localhost:19090");
  for (const value of [
    "https://example.com/path",
    "http://example.com",
    "https://user:password@example.com",
    "garbage",
  ])
    expect(() => saveProxy(s, value)).toThrow();
  expect(s.getItem(proxySettingKey)).toBe("http://localhost:19090");
});
it("keeps the same platform on two proxies separate", () => {
  expect(savedConnectionKey("https://a.example", "drive", "actor", "github")).not.toBe(
    savedConnectionKey("https://b.example", "drive", "actor", "github"),
  );
});
it("migrates legacy connections only for the matching proxy and owner", () => {
  const s = storage();
  const saved = JSON.stringify({
    connection: "state",
    platform: "github",
    drive: "drive",
    actor: "actor",
  });
  s.setItem('localthought-browser:["drive","actor","github"]', saved);
  s.setItem(
    "localthought-browser-v1:state",
    JSON.stringify({
      origin: "https://a.example",
      drive: "drive",
      actor: "actor",
      platform: "github",
    }),
  );
  expect(readSavedConnection(s, "https://b.example", "drive", "actor", "github")).toBeUndefined();
  expect(readSavedConnection(s, "https://a.example", "drive", "actor", "github")).toBe(saved);
  expect(s.getItem(savedConnectionKey("https://a.example", "drive", "actor", "github"))).toBe(
    saved,
  );
});
