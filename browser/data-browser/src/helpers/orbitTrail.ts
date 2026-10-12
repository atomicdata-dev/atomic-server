// The fading trail of the orbiting mark, as on atomic.place's hero: a
// 270-degree arc drawn as bands that each run from their own start angle to
// the end of the arc, so they stack. Opacity climbs from nothing at 3 o'clock
// to solid at the top, where a small dot heads the trail.
//
// Spinner.tsx renders these. index.html carries the same markup inline (it
// cannot import); orbitTrail.test.ts fails when the two differ. To
// regenerate, replace the paths between the `orbit-trail` comments in
// index.html with `orbitTrailMarkup()`.

const CENTER = 50;
const RADIUS = 24;
const SWEEP = 270;
const BAND_COUNT = 48;

export const TRAIL_STROKE_WIDTH = 14;

const RAMP: [number, number][] = [
  [0, 0],
  [75.6, 0.34],
  [176.4, 0.78],
  [248.4, 1],
  [270, 1],
];

export interface TrailBand {
  d: string;
  opacity: number;
  cap: 'round' | 'butt';
}

function ramp(angle: number): number {
  for (let i = 1; i < RAMP.length; i++) {
    const [a1, v1] = RAMP[i];

    if (angle <= a1) {
      const [a0, v0] = RAMP[i - 1];

      return v0 + ((v1 - v0) * (angle - a0)) / (a1 - a0);
    }
  }

  return RAMP[RAMP.length - 1][1];
}

function point(angle: number): [number, number] {
  const rad = (angle * Math.PI) / 180;

  return [
    +(CENTER + RADIUS * Math.cos(rad)).toFixed(2),
    +(CENTER + RADIUS * Math.sin(rad)).toFixed(2),
  ];
}

/** The head of the trail, where the arc ends. */
export const TRAIL_HEAD = { cx: 50, cy: 26, r: 7 };

export function trailBands(n = BAND_COUNT): TrailBand[] {
  const out: TrailBand[] = [];
  const [ex, ey] = point(SWEEP);
  let drawn = 0;

  for (let f = 0; f < n; f++) {
    const start = (SWEEP / n) * f;
    const value = ramp(start + SWEEP / n / 2);
    const gain = drawn >= 1 ? 0 : (value - drawn) / (1 - drawn);

    if (gain <= 0.001) continue;

    const [x, y] = point(start);
    const large = SWEEP - start > 180 ? 1 : 0;

    out.push({
      d: `M${x} ${y} A ${RADIUS} ${RADIUS} 0 ${large} 1 ${ex} ${ey}`,
      opacity: +gain.toFixed(3),
      cap: f === 0 ? 'round' : 'butt',
    });
    drawn += gain * (1 - drawn);
  }

  return out;
}

/** The trail as SVG markup, one element per line, for index.html. */
export function orbitTrailMarkup(): string {
  const paths = trailBands().map(
    b =>
      `<path d="${b.d}" stroke="currentColor" stroke-width="${TRAIL_STROKE_WIDTH}" stroke-linecap="${b.cap}" stroke-opacity="${b.opacity}"/>`,
  );
  const { cx, cy, r } = TRAIL_HEAD;

  return [
    ...paths,
    `<circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor"/>`,
  ].join('\n');
}
