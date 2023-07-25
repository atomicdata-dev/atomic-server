// This application can be used in a Tauri context.

declare global {
  interface Window {
    __TAURI_METADATA__: unknown;
  }
}

export function isRunningInTauri(): boolean {
  return (
    typeof window !== 'undefined' && window.__TAURI_METADATA__ !== undefined
  );
}
