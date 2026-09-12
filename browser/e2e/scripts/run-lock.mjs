import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';

/** A checkout's build/package outputs are mutable; concurrent runs use separate worktrees. */
export function acquireRunLock(directory) {
  const path = join(directory, 'runner.lock');
  const owner = { pid: process.pid, token: randomUUID() };

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      writeFileSync(path, JSON.stringify(owner), { flag: 'wx' });

      return () => {
        try {
          if (JSON.parse(readFileSync(path, 'utf8')).token === owner.token)
            unlinkSync(path);
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
      };
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      // Serialize stale-owner recovery. Without this second exclusive file,
      // two starters could both unlink a dead owner's lock and one could
      // accidentally remove the other's newly acquired lease.
      const recovery = path + '.recovery';

      try {
        writeFileSync(recovery, owner.token, { flag: 'wx' });
      } catch {
        throw new Error(
          'Another runner is inspecting the checkout lease; retry shortly',
        );
      }

      try {
        let existing;

        try {
          existing = JSON.parse(readFileSync(path, 'utf8'));
        } catch (readError) {
          if (readError.code === 'ENOENT') continue;
          throw readError;
        }

        try {
          process.kill(existing.pid, 0);
        } catch (probeError) {
          if (probeError.code === 'ESRCH') {
            unlinkSync(path);
            continue;
          }

          throw probeError;
        }

        throw new Error(
          `E2E runner ${existing.pid} owns this checkout. Wait for it or use another worktree for a concurrent run.`,
        );
      } finally {
        unlinkSync(recovery);
      }
    }
  }

  throw new Error('Could not acquire the E2E checkout lock');
}
