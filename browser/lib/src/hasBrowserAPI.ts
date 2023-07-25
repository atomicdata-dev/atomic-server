export function hasBrowserAPI(): boolean {
  return globalThis === globalThis.window;
}
