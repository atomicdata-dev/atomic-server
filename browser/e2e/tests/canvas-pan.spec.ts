import { test, expect, type Page } from './fixtures';
import { before, devDrive, newResource } from './test-utils';

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

/** The rendered pixels of the canvas — panning must visibly repaint. */
async function canvasPixels(page: Page): Promise<string> {
  return page
    .locator('canvas')
    .first()
    .evaluate(el => (el as HTMLCanvasElement).toDataURL());
}

/** Stroke count of the currently-open canvas, read from the live Store. */
async function strokeCount(page: Page): Promise<number> {
  return page.evaluate(prop => {
    const store = (window as unknown as StoreWindow).store;
    const subject = decodeURIComponent(
      new URLSearchParams(location.search).get('subject')!,
    );
    const strokes = store.getResourceLoading(subject).get(prop);

    return Array.isArray(strokes) ? strokes.length : 0;
  }, STROKE_DATA);
}

test.describe('canvas pan', () => {
  test.beforeEach(before);

  test('space+drag pans the canvas and releasing space restores drawing', async ({
    page,
  }) => {
    await devDrive(page);
    await newResource(CANVAS_CLASS, page);

    const canvas = page.locator('canvas').first();
    await expect(canvas).toBeVisible();
    const box = (await canvas.boundingBox())!;
    const cx = box.x + box.width / 2;
    const cy = box.y + box.height / 2;

    // Draw a stroke so a pan is visible in the rendered pixels.
    await page.mouse.move(cx - 60, cy - 40);
    await page.mouse.down();
    await page.mouse.move(cx, cy, { steps: 4 });
    await page.mouse.up();

    await expect
      .poll(() => canvasPixels(page), { timeout: 15000 })
      .not.toBe('data:,');

    const beforePan = await canvasPixels(page);

    // Hold Space: the canvas shows the grab cursor.
    await page.mouse.move(cx + 40, cy + 40);
    await page.keyboard.down('Space');
    await expect
      .poll(() =>
        canvas.evaluate(el => getComputedStyle(el.parentElement!).cursor),
      )
      .toBe('grab');

    // Drag with the left button: the canvas pans (repaints shifted).
    await page.mouse.down();
    await page.mouse.move(cx + 160, cy + 120, { steps: 6 });
    await expect
      .poll(() => canvasPixels(page), { timeout: 15000 })
      .not.toBe(beforePan);
    await page.mouse.up();
    await page.keyboard.up('Space');

    // Releasing Space returns to drawing: a drag now adds a stroke, not
    // a pan.
    const strokesBefore = await strokeCount(page);

    await page.mouse.move(cx - 80, cy + 60);
    await page.mouse.down();
    await page.mouse.move(cx - 20, cy + 90, { steps: 4 });
    await page.mouse.up();

    await expect
      .poll(() => strokeCount(page), { timeout: 15000 })
      .toBe(strokesBefore + 1);
  });
});
