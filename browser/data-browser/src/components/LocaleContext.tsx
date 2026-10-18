import { useLocalStorage } from '@hooks/useLocalStorage';
import React, { createContext, useContext, useEffect, useState } from 'react';
import { loadLocale } from 'wuchale/load-utils';
import { getBrowserLocale } from '@helpers/preloadLocale';

interface LocaleContextType {
  locale: string;
  setLocale: (locale: string) => void;
}

const LocaleContext = createContext<LocaleContextType>({
  locale: 'en',
  setLocale: () => {},
});

/**
 * Loads the catalog for the chosen locale and renders the app only once it
 * is in.
 *
 * Until a catalog loads, every translated string resolves against an empty
 * one: `[i18n-404:N]` in dev, an empty string in production. The app used to
 * render straight away and remount when the catalog arrived. Anything
 * evaluated in that first mount kept the empty catalog: a toast raised by a
 * mount effect (the dev-drive "Dev agent created" toast, #1799), or a string
 * held in state or a callback. The remount also cost every component its
 * state and re-ran every mount effect (#1645).
 *
 * On a locale switch the current tree stays up until the new catalog is in,
 * then remounts once, so strings outside React state pick up the change.
 */
export const LocaleProvider = ({ children }: React.PropsWithChildren) => {
  const [locale, setLocale] = useLocalStorage(
    'atomic.locale',
    getBrowserLocale(),
  );
  const [loadedLocale, setLoadedLocale] = useState<string | undefined>();

  useEffect(() => {
    let cancelled = false;

    loadLocale(locale)
      .catch(e => {
        // Render anyway: untranslated keys beat a blank app.
        console.error(`Failed to load the "${locale}" catalog`, e);
      })
      .then(() => {
        if (!cancelled) setLoadedLocale(locale);
      });

    return () => {
      cancelled = true;
    };
  }, [locale]);

  return (
    <LocaleContext.Provider value={{ locale, setLocale }}>
      {loadedLocale !== undefined && (
        <React.Fragment key={loadedLocale}>{children}</React.Fragment>
      )}
    </LocaleContext.Provider>
  );
};

export const useLocale = () => {
  return useContext(LocaleContext);
};
