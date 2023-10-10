import { SearchOpts, urls, useServerSearch } from '@tomic/react';
import { useCallback, useMemo, useState } from 'react';
import { useSettings } from '../../../helpers/AppSettings';

export function useResourceSearch(
  searchValue: string,
  classType: string | undefined,
  onResultPick: (result: string) => void,
) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const { drive } = useSettings();

  const searchOpts = useMemo(
    (): SearchOpts => ({
      parents: drive,
      filters: classType ? { [urls.properties.isA]: classType } : undefined,
    }),
    [drive, classType],
  );
  const { results } = useServerSearch(searchValue, searchOpts);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      e.stopPropagation();

      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(i => Math.max(0, i - 1));

        return;
      }

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(i => Math.min(results.length - 1, i + 1));

        return;
      }

      if (e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        onResultPick(results[selectedIndex]);

        return;
      }

      setSelectedIndex(0);
    },
    [results, onResultPick, selectedIndex],
  );

  return {
    results,
    selectedIndex,
    handleKeyDown,
  };
}
