import { test, expect, type Page } from './fixtures';
import { before, devDrive, getCurrentSubject, newResource } from './test-utils';

const CANVAS_CLASS = 'https://atomicdata.dev/ontology/canvas/Canvas';
const STROKE_DATA = 'https://atomicdata.dev/ontology/canvas/strokeData';

/** Minimal shape of the `window.store` exposed in App.tsx. */
type StoreWindow = {
  store: {
    getResourceLoading: (subject: string) => {
      get: (prop: string) => unknown;
    };
    outbox: {
      hasPending: (subject: string) => boolean;
    };
  };
};

/** Wait until the subject's local commits have been acked by the server
 *  (its outbox entry drained). Reloading while commits are still pending
 *  races the refetch: the server would answer with a pre-stroke state. */
async function waitForSubjectSynced(
  page: Page,
  subject: string,
): Promise<void> {
  await expect
    .poll(
      () =>
        page.evaluate(
          subj =>
            (window as unknown as StoreWindow).store.outbox.hasPending(subj),
          subject,
        ),
      { timeout: 15000 },
    )
    .toBe(false);
}

/** Read the number of strokes on the canvas from the page's live Store. */
async function strokeCount(page: Page, subject: string): Promise<number> {
  return page.evaluate(
    ([subj, prop]) => {
      const store = (window as unknown as StoreWindow).store;
      const strokes = store.getResourceLoading(subj).get(prop);

      return Array.isArray(strokes) ? strokes.length : 0;
    },
    [subject, STROKE_DATA] as const,
  );
}

/** Draw one stroke at an offset from the canvas centre, and wait until it
 *  has been committed to the Store. */
async function drawStroke(
  page: Page,
  subject: string,
  dx: number,
  dy: number,
): Promise<void> {
  const canvas = page.locator('canvas').first();
  await expect(canvas).toBeVisible();
  const box = await canvas.boundingBox();

  if (!box) {
    throw new Error('canvas has no bounding box');
  }

  const cx = box.x + box.width / 2 + dx;
  const cy = box.y + box.height / 2 + dy;
  const countBefore = await strokeCount(page, subject);

  await page.mouse.move(cx - 40, cy - 20);
  await page.mouse.down();
  await page.mouse.move(cx, cy, { steps: 4 });
  await page.mouse.move(cx + 40, cy + 20, { steps: 4 });
  await page.mouse.up();

  await expect
    .poll(() => strokeCount(page, subject), { timeout: 15000 })
    .toBe(countBefore + 1);
}

function undoButton(page: Page) {
  return page.locator('button[title^="Undo"]');
}

function redoButton(page: Page) {
  return page.locator('button[title^="Redo"]');
}

test.describe('canvas undo', () => {
  test.beforeEach(before);

  test('tap undo and redo step through edits one at a time', async ({
    page,
  }) => {
    await devDrive(page);
    await newResource(CANVAS_CLASS, page);
    const subject = await getCurrentSubject(page);

    await drawStroke(page, subject, -100, -60);
    await drawStroke(page, subject, 60, 40);
    expect(await strokeCount(page, subject)).toBe(2);

    await undoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(1);

    await undoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(0);

    await redoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(1);

    await redoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(2);
  });

  test('dragging the undo button scrubs history, and redo still walks forward after landing', async ({
    page,
  }) => {
    await devDrive(page);
    await newResource(CANVAS_CLASS, page);
    const subject = await getCurrentSubject(page);

    await drawStroke(page, subject, -120, -80);
    await drawStroke(page, subject, 0, 0);
    await drawStroke(page, subject, 120, 80);
    expect(await strokeCount(page, subject)).toBe(3);

    // Press the undo button and drag left the full scrub width — that
    // sweeps the whole timeline, landing on the initial empty state. The
    // version overlay must show while scrubbing.
    const box = await undoButton(page).boundingBox();

    if (!box) throw new Error('undo button has no bounding box');

    const cx = box.x + box.width / 2;
    const cy = box.y + box.height / 2;

    await page.mouse.move(cx, cy);
    await page.mouse.down();
    await page.mouse.move(cx - 150, cy, { steps: 10 });
    await expect(page.getByText(/Version \d+ \/ \d+/)).toBeVisible();
    await page.mouse.move(cx - 320, cy, { steps: 10 });
    await page.mouse.up();

    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(0);

    // The scrubbed-away states remain redoable — scrubbing must not
    // truncate the future.
    await expect(redoButton(page)).toBeEnabled();
    await redoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(1);
  });

  test('drawing after undo archives the abandoned version; holding undo and releasing on its thumbnail restores it', async ({
    page,
  }) => {
    await devDrive(page);
    await newResource(CANVAS_CLASS, page);
    const subject = await getCurrentSubject(page);

    // Build a 3-stroke version, walk back to 1, then diverge.
    await drawStroke(page, subject, -120, -80);
    await drawStroke(page, subject, 0, 0);
    await drawStroke(page, subject, 120, 80);
    await undoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(2);
    await undoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(1);

    // Divergent edit — the abandoned 3-stroke tip becomes a branch leaf.
    await drawStroke(page, subject, -60, 100);
    expect(await strokeCount(page, subject)).toBe(2);

    // Hold the undo button: the discarded version appears as a thumbnail.
    const box = await undoButton(page).boundingBox();

    if (!box) throw new Error('undo button has no bounding box');

    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();

    const tile = page.locator('[data-branch-id]').first();
    await expect(tile).toBeVisible();

    // Drag over the thumbnail and release — restores the 3-stroke version.
    const tileBox = await tile.boundingBox();

    if (!tileBox) throw new Error('branch tile has no bounding box');

    await page.mouse.move(
      tileBox.x + tileBox.width / 2,
      tileBox.y + tileBox.height / 2,
      { steps: 8 },
    );
    await page.mouse.up();

    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(3);

    // The restore itself is undoable: tapping undo returns to the
    // divergent 2-stroke state.
    await undoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(2);
  });

  test('undo works right after a cold reload of a canvas with history', async ({
    page,
  }) => {
    await devDrive(page);
    await newResource(CANVAS_CLASS, page);
    const subject = await getCurrentSubject(page);

    await drawStroke(page, subject, -80, -40);
    await drawStroke(page, subject, 80, 40);

    // Both stroke commits must be server-acked before reloading —
    // otherwise the post-reload refetch races the drain and can answer
    // with a pre-stroke state.
    await waitForSubjectSynced(page, subject);

    // Wipe the locally persisted undo state and reload: the undo stack must
    // be bootstrapped from the resource's Loro history after the WASM
    // loads (this used to leave the button permanently disabled).
    await page.evaluate(subj => {
      localStorage.removeItem(`canvas-undo:${subj}`);
    }, subject);
    await page.reload();

    await expect(page.locator('canvas').first()).toBeVisible({
      timeout: 20000,
    });

    // Precondition: the strokes survived the reload. Without history there
    // is nothing to undo and the button is CORRECTLY disabled — failing
    // here means the environment lost the data across the reload (e.g.
    // the server rejected the stroke commits), not that undo is broken.
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .toBe(2);

    await expect(undoButton(page)).toBeEnabled({ timeout: 20000 });

    await undoButton(page).click();
    await expect
      .poll(() => strokeCount(page, subject), { timeout: 15000 })
      .not.toBe(2);
  });
});
