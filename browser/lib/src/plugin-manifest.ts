import type { JSONValue } from './value.js';

/**
 * What a plugin declares it needs.
 *
 * Written in the plugin's own source, beside the code that uses it:
 *
 * ```js
 * export const manifest = {
 *   secrets: [{ name: 'google', origin: 'https://www.googleapis.com',
 *               description: 'Google Calendar API token' }],
 * };
 * ```
 *
 * Two things follow from putting it there rather than in resource properties.
 * The declaration cannot drift from the code that spends it — the same file
 * says `secret:google` and asks for `google`. And an author, human or model,
 * writes one artifact rather than remembering to fill in a form elsewhere.
 */
export interface DeclaredSecret {
  /** Referred to in the source as `secret:<name>`. */
  name: string;
  /** The exact origin it may be sent to. */
  origin: string;
  /** Shown to whoever has to find the credential. */
  description?: string;
}

export interface PluginManifest {
  secrets: DeclaredSecret[];
}

/**
 * Normalizes whatever a plugin exported as `manifest`.
 *
 * Same posture as `parseVerdict`: the export is authored by an LLM as often as
 * a person, so anything malformed is dropped rather than trusted, and a plugin
 * that declares nothing usable declares nothing.
 */
export function parseManifest(raw: unknown): PluginManifest {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { secrets: [] };
  }

  const secrets = (raw as { secrets?: unknown }).secrets;

  if (!Array.isArray(secrets)) return { secrets: [] };

  const seen = new Set<string>();

  return {
    secrets: secrets.flatMap(entry => {
      if (!entry || typeof entry !== 'object') return [];

      const { name, origin, description } = entry as Record<string, JSONValue>;

      if (typeof name !== 'string' || name.length === 0) return [];

      if (typeof origin !== 'string' || origin.length === 0) return [];

      // A name declared twice would render two slots writing to one secret.
      if (seen.has(name)) return [];

      seen.add(name);

      return [
        {
          name,
          origin,
          ...(typeof description === 'string' ? { description } : {}),
        },
      ];
    }),
  };
}

/**
 * Secret names a plugin's source actually spends, whether or not it declared
 * them.
 *
 * A plugin that writes `secret:google_calendar_token` needs that credential
 * even if it forgot to say so — and an author who forgot is exactly the one who
 * cannot work out where to enter it. Scanning the source means the page can
 * offer a slot anyway, asking for the origin the declaration would have named.
 */
export function secretsMentionedIn(source: string): string[] {
  const found = new Set<string>();

  for (const match of source.matchAll(/secret:([A-Za-z0-9_-]+)/g)) {
    found.add(match[1]);
  }

  return [...found].sort();
}
