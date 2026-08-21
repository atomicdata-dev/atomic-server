import { describe, expect, it } from 'vitest';
import {
  originsMentionedIn,
  parseManifest,
  secretsMentionedIn,
} from './plugin-manifest.js';

describe('parseManifest', () => {
  it('keeps a declaration a plugin actually made', () => {
    expect(
      parseManifest({
        secrets: [
          {
            name: 'google',
            origin: 'https://www.googleapis.com',
            description: 'Calendar token',
          },
        ],
      }),
    ).toEqual({
      secrets: [
        {
          name: 'google',
          origin: 'https://www.googleapis.com',
          description: 'Calendar token',
        },
      ],
    });
  });

  it('treats a plugin that declares nothing as declaring nothing', () => {
    for (const raw of [undefined, null, 'nope', 42, [], {}, { secrets: 'x' }]) {
      expect(parseManifest(raw)).toEqual({ secrets: [] });
    }
  });

  it('drops a secret with no name or no origin', () => {
    const manifest = parseManifest({
      secrets: [
        { name: 'ok', origin: 'https://a.test' },
        { name: 'no-origin' },
        { origin: 'https://b.test' },
        { name: '', origin: 'https://c.test' },
        'not an object',
      ],
    });

    expect(manifest.secrets.map(s => s.name)).toEqual(['ok']);
  });

  it('keeps the first of a repeated name', () => {
    // Two slots writing to one secret would silently overwrite each other.
    const manifest = parseManifest({
      secrets: [
        { name: 'dup', origin: 'https://a.test' },
        { name: 'dup', origin: 'https://b.test' },
      ],
    });

    expect(manifest.secrets).toHaveLength(1);
    expect(manifest.secrets[0].origin).toBe('https://a.test');
  });

  it('leaves out a description that is not a string', () => {
    const manifest = parseManifest({
      secrets: [{ name: 'a', origin: 'https://a.test', description: 7 }],
    });

    expect(manifest.secrets[0]).toEqual({
      name: 'a',
      origin: 'https://a.test',
    });
  });
});

describe('secretsMentionedIn', () => {
  it('finds what a plugin spends even when it declared nothing', () => {
    const source = `
      export function run(ctx) {
        return ctx.http({
          url: 'https://api.test/x',
          headers: { Authorization: 'Bearer secret:google_calendar_token' },
        });
      }`;

    expect(secretsMentionedIn(source)).toEqual(['google_calendar_token']);
  });

  it('lists each name once, in a stable order', () => {
    const source = 'secret:b secret:a secret:b';

    expect(secretsMentionedIn(source)).toEqual(['a', 'b']);
  });

  it('finds nothing in a plugin that spends nothing', () => {
    expect(secretsMentionedIn('export function run() { return {}; }')).toEqual(
      [],
    );
  });
});

describe('originsMentionedIn', () => {
  it('reads the origin out of a URL the plugin builds', () => {
    const source =
      'const url = `https://www.googleapis.com/calendar/v3/calendars/${id}/events`;';

    expect(originsMentionedIn(source)).toEqual(['https://www.googleapis.com']);
  });

  it('keeps the port, since an origin includes it', () => {
    expect(originsMentionedIn("'http://localhost:9883/x'")).toEqual([
      'http://localhost:9883',
    ]);
  });

  it('lists each origin once', () => {
    const source = "'https://a.test/x' 'https://a.test/y' 'https://b.test/z'";

    expect(originsMentionedIn(source)).toEqual([
      'https://a.test',
      'https://b.test',
    ]);
  });

  it('finds nothing when every URL is assembled at runtime', () => {
    // Which is exactly the case nobody should be pre-authorising by guess.
    expect(originsMentionedIn('const url = base + path;')).toEqual([]);
  });
});
