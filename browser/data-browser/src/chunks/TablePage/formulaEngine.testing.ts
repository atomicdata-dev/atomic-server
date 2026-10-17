import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { provideFormulaEngine } from './formulaEngine';

/**
 * Loads the real evaluator (the built `public/wasm` bundle, which `pnpm run -r
 * build` produces) for a test, since nothing can fetch it there. Tests then run
 * the same Rust the store does rather than a stand-in.
 */
export async function useRealFormulaEngine(): Promise<void> {
  const dir = resolve(__dirname, '../../../public/wasm');
  const glue = await import(/* @vite-ignore */ `${dir}/atomic_wasm.js`);

  glue.initSync({ module: readFileSync(`${dir}/atomic_wasm_bg.wasm`) });
  provideFormulaEngine(glue);
}
