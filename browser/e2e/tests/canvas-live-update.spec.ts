import { test, expect, type Page } from './fixtures';
import {
  before,
  devDrive,
  getCurrentSubject,
  makeDrivePublic,
  newResource,
  openNewSubjectWindow,
} from './test-utils';

const CANVAS_CLASS = 'https://atomicdata.dev/ontology/canvas/Canvas';
const STROKE_DATA = 'https://atomicdata.dev/ontology/canvas/strokeData';

/** Minimal shape of the `window.store` exposed in App.tsx. */
type StoreWindow = {
  store: {
    getResourceLoading: (subject: string) => {
      get: (prop: string) => unknown;
    };
  };
};

/** Read the number of strokes on a canvas from the page's live Store — the
 *  same in-memory resource the canvas renders from, so this reflects live
 *  updates without a reload. */
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

/** The rendered pixels of the canvas element. Changes only when the canvas
 *  component actually repaints — which is what "live update" means visually,
 *  distinct from the underlying Store merely receiving the data. */
async function canvasPixels(page: Page): Promise<string> {
  return page
    .locator('canvas')
    .first()
    .evaluate(el => (el as HTMLCanvasElement).toDataURL());
}

/** Draw one stroke on the canvas element via pointer events. */
async function drawStroke(page: Page): Promise<void> {
  const canvas = page.locator('canvas').first();
  await expect(canvas).toBeVisible();
  const box = await canvas.boundingBox();

  if (!box) {
    throw new Error('canvas has no bounding box');
  }

  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;

  await page.mouse.move(cx - 60, cy - 40);
  await page.mouse.down();
  await page.mouse.move(cx - 20, cy + 10, { steps: 4 });
  await page.mouse.move(cx + 40, cy + 40, { steps: 4 });
  await page.mouse.up();
}

test.describe('canvas live update', () => {
  test.beforeEach(before);

  test('a stroke drawn in one session appears live in another session viewing the same canvas', async ({
    page,
    browser,
  }) => {
    // Session A: dev drive + a canvas, signed in.
    const secret = await devDrive(page);
    await newResource(CANVAS_CLASS, page);
    const canvasSubject = await getCurrentSubject(page);

    // Session B: a second context, SAME agent, viewing the same canvas.
    const pageB = await openNewSubjectWindow(browser, canvasSubject, secret);
    await expect(pageB.locator('canvas').first()).toBeVisible({
      timeout: 20000,
    });

    // Both start empty.
    expect(await strokeCount(page, canvasSubject)).toBe(0);
    expect(await strokeCount(pageB, canvasSubject)).toBe(0);

    // Baseline of session B's rendered canvas (empty), to detect a repaint.
    const pixelsBBefore = await canvasPixels(pageB);

    // A draws a stroke — it saves + commits immediately (pushListItem + save).
    await drawStroke(page);

    // Sanity: the draw landed in session A's own store and repainted A.
    await expect
      .poll(() => strokeCount(page, canvasSubject), { timeout: 15000 })
      .toBe(1);

    // Session B's Store receives the stroke over WS fan-out.
    await expect
      .poll(() => strokeCount(pageB, canvasSubject), { timeout: 15000 })
      .toBe(1);

    // The actual live-update assertion: session B's CANVAS repaints to show
    // the stroke, without a reload. The Store having the data (above) is not
    // enough — the canvas copies strokes into local state on a change event
    // and only repaints then. If that event never fires for a remote update,
    // the Store is up to date but the drawing on screen is not.
    await expect
      .poll(() => canvasPixels(pageB), { timeout: 15000 })
      .not.toBe(pixelsBBefore);

    await pageB.context().close();
  });

  // A stroke committed by the canvas owner must reach a DIFFERENT viewer
  // subscribed to the same public drive. This used to fail: the browser only
  // sent the drive SUB inside its auth handshake, so an anonymous viewer never
  // subscribed, and setting the drive after connect (deep-link adoption) never
  // (re)subscribed either — the viewer's Store stayed empty. Fixed by making
  // the drive subscription connection-lifecycle-driven (see websockets.ts).
  test('a stroke drawn by the owner appears live for a different viewer on a public drive', async ({
    page,
    browser,
  }) => {
    // Owner: dev drive made public, plus a canvas.
    await devDrive(page);
    await makeDrivePublic(page);
    await newResource(CANVAS_CLASS, page);
    const canvasSubject = await getCurrentSubject(page);

    // Viewer: a DIFFERENT identity (fresh anonymous context) watching the
    // same canvas.
    const viewer = await openNewSubjectWindow(browser, canvasSubject);
    await expect(viewer.locator('canvas').first()).toBeVisible({
      timeout: 20000,
    });

    expect(await strokeCount(viewer, canvasSubject)).toBe(0);

    await drawStroke(page);

    // The owner's own store gets it (sanity — the draw + commit worked).
    await expect
      .poll(() => strokeCount(page, canvasSubject), { timeout: 15000 })
      .toBe(1);

    // The viewer must receive the stroke live over WS fan-out. This is the
    // assertion that currently fails: the viewer's Store stays empty.
    await expect
      .poll(() => strokeCount(viewer, canvasSubject), { timeout: 15000 })
      .toBe(1);

    await viewer.context().close();
  });
});
