// Shell-agnostic `build`: the previous inline `if [ ... ]` script only worked
// under sh/bash and broke under cmd.exe (Tauri Windows build).
import { spawnSync } from 'node:child_process';

const run = (cmd, args) => {
  const res = spawnSync(cmd, args, { stdio: 'inherit', shell: true });

  if (res.status !== 0) {
    process.exit(res.status ?? 1);
  }
};

if (process.env.SKIP_WASM_BUILD === '1') {
  console.log('SKIP_WASM_BUILD=1, skipping wasm-pack');
} else {
  run('pnpm', ['build:wasm']);
}

run('vite', ['build']);
