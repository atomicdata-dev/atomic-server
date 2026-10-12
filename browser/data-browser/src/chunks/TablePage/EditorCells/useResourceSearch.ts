import {
  core,
  isAtomicIdentifier,
  SearchOpts,
  useArray,
  useResource,
  useResources,
  useServerSearch,
} from '@tomic/react';
import { useCallback, useMemo } from 'react';
import { useSettings } from '@helpers/AppSettings';
import { agentMatchesQuery } from '@helpers/mentionSearch';
import { useSelectedIndex } from '@hooks/useSelectedIndex';

/** A pasted subject the user means literally, so it needs no search hit. */
export function pastedSubject(searchValue: string): string | undefined {
  const value = searchValue.trim();

  if (/\s/.test(value)) return undefined;

  return isAtomicIdentifier(value) || /^https?:\/\/\S+$/.test(value)
    ? value
    : undefined;
}

const stableEmpty: string[] = [];

/**
 * The agents with direct read or write rights on the drive. An agent's own
 * data is not part of the drive, so search never finds them; the rights list
 * is the one place the drive names them, and each is fetched by subject.
 */
export function useDriveMembers(
  drive: string,
  classType: string | undefined,
  searchValue: string,
): string[] {
  const driveResource = useResource(drive);
  const [writers = stableEmpty] = useArray(
    driveResource,
    core.properties.write,
  );
  const [readers = stableEmpty] = useArray(driveResource, core.properties.read);
  const wantsAgents = !classType || classType === core.classes.agent;

  const members = useMemo(
    () => (wantsAgents ? [...new Set([...writers, ...readers])] : stableEmpty),
    [wantsAgents, writers, readers],
  );
  const loaded = useResources(members);
  const needle = searchValue.trim().toLowerCase();

  return useMemo(() => {
    if (!needle) return members;

    return members.filter(subject => {
      return agentMatchesQuery(subject, loaded.get(subject), needle);
    });
  }, [members, loaded, needle]);
}

export function useResourceSearch(
  searchValue: string,
  classType: string | undefined,
  onResultPick: (result: string, source: 'keyboard' | 'mouse') => void,
  valuesWhenEmpty: string[] = [],
) {
  const { drive } = useSettings();

  const searchOpts = useMemo(
    (): SearchOpts => ({
      parents: drive,
      filters: classType ? { [core.properties.isA]: classType } : undefined,
      include: false,
    }),
    [drive, classType],
  );
  const { results } = useServerSearch(searchValue, searchOpts);

  const members = useDriveMembers(drive, classType, searchValue);
  const pasted = pastedSubject(searchValue);

  const list = useMemo(() => {
    const base =
      !searchValue && valuesWhenEmpty !== undefined ? valuesWhenEmpty : results;
    const extra = [...(pasted ? [pasted] : []), ...members];

    return [...new Set([...extra, ...base])];
  }, [searchValue, valuesWhenEmpty, results, members, pasted]);
  const { selectedIndex, onKeyDown, onMouseOver, onClick, usingKeyboard } =
    useSelectedIndex(
      list,
      (i, source) => {
        if (i === undefined) return;

        onResultPick(list[i], source);
      },
      { initialIndex: 0, key: searchValue },
    );
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Tab') {
        return;
      }

      if (e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
      }

      onKeyDown(e);
    },
    [onKeyDown],
  );

  return {
    results: list,
    selectedIndex,
    handleKeyDown,
    onMouseOver,
    onClick,
    usingKeyboard,
  };
}
