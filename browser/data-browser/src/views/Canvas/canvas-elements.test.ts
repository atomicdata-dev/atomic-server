import { describe, expect, it } from 'vitest';
import type { CanvasStroke } from '@tomic/lib';
import {
  contentBounds,
  elementBounds,
  lassoSelect,
  pointInPolygon,
  transformSelection,
} from './canvas-elements';

const stroke = (path: [number, number][], width = 2): CanvasStroke => ({
  color: 0xff000000,
  width,
  path,
});

const square: [number, number][] = [
  [0, 0],
  [100, 0],
  [100, 100],
  [0, 100],
];

describe('canvas-elements', () => {
  it('tests points against a polygon', () => {
    expect(pointInPolygon(50, 50, square)).toBe(true);
    expect(pointInPolygon(150, 50, square)).toBe(false);
  });

  it('lasso picks strokes with a point inside and images by their box', () => {
    const inside = stroke([
      [10, 10],
      [20, 20],
    ]);
    const outside = stroke([
      [200, 200],
      [210, 210],
    ]);
    const image: CanvasStroke = {
      ...stroke([[40, 40]], 0.01),
      kind: 'image',
      src: 'data:,',
      w: 20,
      h: 20,
    };

    expect(lassoSelect(square, [inside, outside, image])).toEqual([0, 2]);
  });

  it('scales strokes, text and images around a point and moves them', () => {
    const text: CanvasStroke = {
      ...stroke([[10, 10]], 0.01),
      kind: 'text',
      text: 'hi',
      size: 20,
    };
    const image: CanvasStroke = {
      ...stroke([[0, 0]], 0.01),
      kind: 'image',
      src: 'data:,',
      w: 10,
      h: 20,
    };
    const [s, t, i] = transformSelection(
      [
        stroke(
          [
            [10, 10],
            [20, 10],
          ],
          4,
        ),
        text,
        image,
      ],
      [0, 1, 2],
      2,
      0,
      0,
      5,
      5,
    );

    expect(s.path).toEqual([
      [25, 25],
      [45, 25],
    ]);
    expect(s.width).toBe(8);
    expect(t.path).toEqual([[25, 25]]);
    expect(t.size).toBe(40);
    expect([i.w, i.h]).toEqual([20, 40]);
  });

  it('leaves unselected elements untouched', () => {
    const a = stroke([[1, 1]]);

    expect(transformSelection([a], [], 3, 0, 0, 9, 9)[0]).toBe(a);
  });

  it('content bounds include images by their box, not just strokes', () => {
    const image: CanvasStroke = {
      ...stroke([[500, 400]], 0.01),
      kind: 'image',
      src: 'data:,',
      w: 200,
      h: 100,
    };
    const line = stroke(
      [
        [0, 0],
        [10, 10],
      ],
      0,
    );

    expect(contentBounds([line])).toEqual({
      minX: 0,
      minY: 0,
      maxX: 10,
      maxY: 10,
    });
    expect(contentBounds([line, image])).toEqual({
      minX: 0,
      minY: 0,
      maxX: 700,
      maxY: 500,
    });
    expect(contentBounds([image])).toEqual({
      minX: 500,
      minY: 400,
      maxX: 700,
      maxY: 500,
    });
    expect(contentBounds([])).toBeNull();
  });

  it('pads stroke bounds by half the width', () => {
    expect(
      elementBounds(
        stroke(
          [
            [0, 0],
            [10, 10],
          ],
          4,
        ),
      ),
    ).toEqual({
      minX: -2,
      minY: -2,
      maxX: 12,
      maxY: 12,
    });
  });
});
