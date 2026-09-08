/**
 * Profiling probe for table-template creation.
 *
 * Not a budget gate — it drives the New Table dialog with a template that uses
 * every capability (select columns with tags, computed columns, views, totals)
 * and prints the wall-clock plus the `table.*` / `resource.save` / `commit.*`
 * rollup so the slow leg of the create is visible at a glance.
 *
 *   npx playwright test tests/table-create-perf.spec.ts --workers=1 --reporter=line
 *
 * Read the `[TABLE-PERF]` lines.
 */

import { test, expect } from './fixtures';
import { before, newResource } from './test-utils';
import { resetPerfTrace } from './perf-attach';

const PREFIXES = [
  'table.',
  'resource.',
  'commit.',
  'store.postCommit',
  'clientdb.',
  'ws.',
];

async function rollup(page: import('@playwright/test').Page) {
  return page.evaluate(prefixes => {
    const snap = (
      window as unknown as {
        __atomicPerf?: {
          snapshot(): {
            windowMs: number;
            rollup: Array<{
              name: string;
              count: number;
              totalMs: number;
              maxMs: number;
              avgMs: number;
            }>;
          };
        };
      }
    ).__atomicPerf?.snapshot();

    if (!snap) return undefined;

    return snap.rollup
      .filter(r => prefixes.some(p => r.name.startsWith(p)))
      .map(r => ({
        name: r.name,
        n: r.count,
        total: Math.round(r.totalMs),
        avg: Math.round(r.avgMs * 10) / 10,
        max: Math.round(r.maxMs),
      }));
  }, PREFIXES);
}

test.describe('table create perf', () => {
  test.beforeEach(before);
  test.slow();

  for (const template of ['Project tasks', 'Issue Tracker', 'Expenses']) {
    test(`create from "${template}"`, async ({ page }) => {
      await newResource('table', page);
      await page.getByRole('button', { name: new RegExp(template) }).click();
      await page.getByPlaceholder('New Table').fill(`Perf ${template}`);

      await resetPerfTrace(page);
      const started = Date.now();
      await page.getByRole('button', { name: 'Create' }).click();
      // The table page, whichever view the template defaults to — a kanban
      // template opens on its board, not on a grid.
      await expect(
        page.getByRole('heading', { name: `Perf ${template}` }).first(),
      ).toBeVisible({ timeout: 60_000 });
      const wallMs = Date.now() - started;

      const rows = await rollup(page);
      // eslint-disable-next-line no-console
      console.log(
        `[TABLE-PERF] ${template}: click→grid ${wallMs}ms\n` +
          (rows ?? [])
            .sort((a, b) => b.total - a.total)
            .map(
              r =>
                `  ${r.name.padEnd(32)} n=${String(r.n).padStart(3)} total=${String(r.total).padStart(6)}ms avg=${r.avg}ms max=${r.max}ms`,
            )
            .join('\n'),
      );

      expect(rows?.length ?? 0).toBeGreaterThan(0);
    });
  }
});
