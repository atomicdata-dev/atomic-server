// @wc-ignore-file
import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { orbitTrailMarkup, trailBands } from './orbitTrail';

const brandSvgUrl = new URL(
  '../../../../brand/src/place-mark.svg',
  import.meta.url,
);

describe('orbitTrail', () => {
  it('starts at 3 o clock and ends at the top, fading in', () => {
    const bands = trailBands();

    expect(bands[0].d.startsWith('M74 50 A 24 24 0 1 1 50 26')).toBe(true);
    expect(bands.every(b => b.d.endsWith('50 26'))).toBe(true);
    expect(bands[0].cap).toBe('round');
    expect(bands.slice(1).every(b => b.cap === 'butt')).toBe(true);
  });

  it('is the same markup index.html draws before the app loads', () => {
    const html = readFileSync(
      new URL('../../index.html', import.meta.url),
      'utf8',
    );
    const inline = html
      .split(/<!-- orbit-trail:start[^>]*-->|<!-- orbit-trail:end -->/)[1]
      ?.trim()
      .split('\n')
      .map(line => line.trim())
      .join('\n');

    expect(inline).toBe(orbitTrailMarkup());
  });

  // The Dagger test container mounts only browser/, so brand/ is absent
  // there; the check runs in local and full-checkout runs.
  it.skipIf(!existsSync(brandSvgUrl))(
    'is the same trail brand/src/place-mark.svg draws, in white',
    () => {
      const svg = readFileSync(brandSvgUrl, 'utf8');
      const inline = svg
        .split(/<!-- orbit-trail:start -->|<!-- orbit-trail:end -->/)[1]
        ?.trim()
        .split('\n')
        .map(line => line.trim())
        .join('\n');

      expect(inline).toBe(orbitTrailMarkup('#fff'));
    },
  );
});
