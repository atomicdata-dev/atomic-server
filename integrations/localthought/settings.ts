/** Browser-local proxy preferences and origin-scoped connection discovery. */
import { DEFAULT_PROXY, proxyOrigin } from "./browser";

export const proxySettingKey = "integration-proxy-url";

export function configuredProxy(storage: Pick<Storage, "getItem">, fallback = DEFAULT_PROXY) {
  return proxyOrigin(storage.getItem(proxySettingKey) || fallback);
}

export function saveProxy(storage: Pick<Storage, "setItem" | "removeItem">, value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    storage.removeItem(proxySettingKey);
    return;
  }
  const origin = proxyOrigin(trimmed.replace(/\/$/, ""));
  storage.setItem(proxySettingKey, origin);
}

export function savedConnectionKey(origin: string, drive: string, actor: string, platform: string) {
  return `localthought-browser:${JSON.stringify([proxyOrigin(origin), drive, actor, platform])}`;
}

export function readSavedConnection(
  storage: Pick<Storage, "getItem" | "setItem">,
  origin: string,
  drive: string,
  actor: string,
  platform: string,
) {
  const key = savedConnectionKey(origin, drive, actor, platform);
  const current = storage.getItem(key);
  if (current) return current;
  const legacy = storage.getItem(
    `localthought-browser:${JSON.stringify([drive, actor, platform])}`,
  );
  if (!legacy) return;
  try {
    const saved = JSON.parse(legacy);
    const credential = JSON.parse(
      storage.getItem(`localthought-browser-v1:${saved.connection}`) || "null",
    );
    if (
      credential?.origin !== origin ||
      credential.drive !== drive ||
      credential.actor !== actor ||
      credential.platform !== platform
    )
      return;
    storage.setItem(key, legacy);
    return legacy;
  } catch {
    return;
  }
}
