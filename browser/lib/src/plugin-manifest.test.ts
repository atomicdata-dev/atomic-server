import { describe, expect, it } from 'vitest';
import { parseManifest } from './plugin-manifest.js';

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
