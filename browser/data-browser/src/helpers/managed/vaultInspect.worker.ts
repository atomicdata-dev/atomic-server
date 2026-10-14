// @wc-ignore-file
import type { PackInspection } from './vaultContents';
import type { DriveKeyHandle } from './vault';

type InspectorWasm = {
  default: (init: {
    module_or_path: WebAssembly.Module | string;
  }) => Promise<unknown>;
  vaultInspectPack: (
    key: Uint8Array,
    epoch: number,
    sealed: Uint8Array,
  ) => PackInspection;
};
let ready: Promise<InspectorWasm>;
let key: DriveKeyHandle;

self.onmessage = async ({ data }) => {
  if ('key' in data) {
    key = data.key;
    ready = import(/* @vite-ignore */ data.jsUrl).then(async wasm => {
      await wasm.default({ module_or_path: data.source });

      return wasm;
    });
    // Surface initialization failures through the requesting object's reply.
    void ready.catch(() => {});

    return;
  }

  try {
    const wasm = await ready;
    self.postMessage({
      id: data.id,
      result: wasm.vaultInspectPack(key.driveKey, key.keyEpoch, data.sealed),
    });
  } catch (error) {
    self.postMessage({
      id: data.id,
      error: error instanceof Error ? error.message : String(error),
    });
  }
};
