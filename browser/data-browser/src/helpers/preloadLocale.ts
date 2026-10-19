import { loadLocale } from 'wuchale/load-utils';

// Start fetching the translation catalog while the rest of the app is still
// being fetched and evaluated. LocaleProvider holds the whole app back until
// the catalog is in, and used to begin loading it only from an effect after
// its own first commit: a serial hop in front of the first real render.
//
// No React imports here: this must stay the first import in index.tsx.
export const SUPPORTED_LOCALES = ['en', 'es', 'fr', 'de'];

export function getBrowserLocale(): string {
  const locales = navigator.languages.map(x => x.trim().split(/-|_/)[0]);

  return locales.find(x => SUPPORTED_LOCALES.includes(x)) ?? 'en';
}

function startLocale(): string {
  try {
    const stored = window.localStorage.getItem('atomic.locale');

    if (stored) return JSON.parse(stored) as string;
  } catch {
    // Fall through to the browser language.
  }

  return getBrowserLocale();
}

void loadLocale(startLocale()).catch(() => undefined);
