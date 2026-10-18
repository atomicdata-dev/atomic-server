import type { CanvasStroke } from '@tomic/lib';

export type Bounds = { minX: number; minY: number; maxX: number; maxY: number };

/** Line height of text elements, as a multiple of the font size. */
export const TEXT_LINE_HEIGHT = 1.25;
export const TEXT_FONT_FAMILY = 'system-ui, -apple-system, sans-serif';

let measureCtx: CanvasRenderingContext2D | null = null;

function textWidth(text: string, size: number): number {
  measureCtx ??= document.createElement('canvas').getContext('2d');

  if (!measureCtx) {
    return text.length * size * 0.55;
  }

  measureCtx.font = `${size}px ${TEXT_FONT_FAMILY}`;

  return measureCtx.measureText(text).width;
}

/** Axis-aligned bounds of an element in canvas coordinates. */
export function elementBounds(el: CanvasStroke): Bounds {
  const [ax, ay] = el.path[0];

  if (el.kind === 'image') {
    return {
      minX: ax,
      minY: ay,
      maxX: ax + (el.w ?? 0),
      maxY: ay + (el.h ?? 0),
    };
  }

  if (el.kind === 'text') {
    const size = el.size ?? 24;
    const lines = (el.text ?? '').split('\n');
    const width = Math.max(
      size * 0.5,
      ...lines.map(line => textWidth(line, size)),
    );

    return {
      minX: ax,
      minY: ay,
      maxX: ax + width,
      maxY: ay + lines.length * size * TEXT_LINE_HEIGHT,
    };
  }

  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;

  for (const [x, y] of el.path) {
    minX = Math.min(minX, x);
    minY = Math.min(minY, y);
    maxX = Math.max(maxX, x);
    maxY = Math.max(maxY, y);
  }

  const pad = el.width / 2;

  return {
    minX: minX - pad,
    minY: minY - pad,
    maxX: maxX + pad,
    maxY: maxY + pad,
  };
}

export function unionBounds(list: Bounds[]): Bounds | null {
  if (list.length === 0) return null;

  return list.reduce((a, b) => ({
    minX: Math.min(a.minX, b.minX),
    minY: Math.min(a.minY, b.minY),
    maxX: Math.max(a.maxX, b.maxX),
    maxY: Math.max(a.maxY, b.maxY),
  }));
}

/** Bounds of everything on the canvas (strokes, text and images), or null when empty. */
export function contentBounds(elements: CanvasStroke[]): Bounds | null {
  return unionBounds(
    elements.filter(el => el.path.length > 0).map(elementBounds),
  );
}

/** Ray-casting point-in-polygon test. */
export function pointInPolygon(
  x: number,
  y: number,
  polygon: [number, number][],
): boolean {
  let inside = false;

  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, yi] = polygon[i];
    const [xj, yj] = polygon[j];

    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) {
      inside = !inside;
    }
  }

  return inside;
}

/**
 * Whether the lasso picks an element: any point of a stroke inside the loop,
 * or, for text and images, the centre or any corner of its box.
 */
export function lassoHits(
  polygon: [number, number][],
  el: CanvasStroke,
): boolean {
  if (polygon.length < 3) return false;

  if (el.kind) {
    const b = elementBounds(el);
    const probes: [number, number][] = [
      [(b.minX + b.maxX) / 2, (b.minY + b.maxY) / 2],
      [b.minX, b.minY],
      [b.maxX, b.minY],
      [b.minX, b.maxY],
      [b.maxX, b.maxY],
    ];

    return probes.some(([x, y]) => pointInPolygon(x, y, polygon));
  }

  return el.path.some(([x, y]) => pointInPolygon(x, y, polygon));
}

/** Indices of the elements the lasso loop encloses. */
export function lassoSelect(
  polygon: [number, number][],
  elements: CanvasStroke[],
): number[] {
  const picked: number[] = [];

  elements.forEach((el, i) => {
    if (lassoHits(polygon, el)) picked.push(i);
  });

  return picked;
}

/**
 * Scale an element by `factor` around `(ox, oy)`, then move it by `(dx, dy)`.
 * Pure: returns a new element.
 */
export function transformElement(
  el: CanvasStroke,
  factor: number,
  ox: number,
  oy: number,
  dx: number,
  dy: number,
): CanvasStroke {
  const map = ([x, y]: [number, number]): [number, number] => [
    ox + (x - ox) * factor + dx,
    oy + (y - oy) * factor + dy,
  ];

  if (el.kind === 'text') {
    return { ...el, path: [map(el.path[0])], size: (el.size ?? 24) * factor };
  }

  if (el.kind === 'image') {
    return {
      ...el,
      path: [map(el.path[0])],
      w: (el.w ?? 0) * factor,
      h: (el.h ?? 0) * factor,
    };
  }

  return { ...el, path: el.path.map(map), width: el.width * factor };
}

/** Apply one transform to the selected indices of a list. */
export function transformSelection(
  elements: CanvasStroke[],
  selection: number[],
  factor: number,
  ox: number,
  oy: number,
  dx: number,
  dy: number,
): CanvasStroke[] {
  const picked = new Set(selection);

  return elements.map((el, i) =>
    picked.has(i) ? transformElement(el, factor, ox, oy, dx, dy) : el,
  );
}
