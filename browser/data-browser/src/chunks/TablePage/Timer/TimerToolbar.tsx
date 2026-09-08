import {
  JSONValue,
  Property,
  Resource,
  commits,
  core,
  useStore,
  type Collection,
} from '@tomic/react';
import { useCallback, useState, type JSX } from 'react';
import toast from 'react-hot-toast';
import { styled } from 'styled-components';
import { FaPlay } from 'react-icons/fa6';
import { Button } from '@components/Button';
import { Checkbox } from '@components/forms/Checkbox';
import { InputStyled } from '@components/forms/InputStyles';

interface TimerToolbarProps {
  tableSubject: string;
  tableClass: Resource;
  collection: Collection;
  startProp: Property;
  endProp: Property;
  exclusive: boolean;
  setExclusive: (exclusive: boolean) => void;
  /** Tells the grid its member count grew — see `incrementMemberCount`. */
  onEntryCreated: () => void;
}

/**
 * Sits above the grid: name a thing and start timing it. Everything else about
 * an entry — its project, its timestamps — is edited in the table itself, so
 * this stays a single field rather than a second form.
 */
export function TimerToolbar({
  tableSubject,
  tableClass,
  collection,
  startProp,
  endProp,
  exclusive,
  setExclusive,
  onEntryCreated,
}: TimerToolbarProps): JSX.Element {
  const store = useStore();
  const [name, setName] = useState('');

  const handleStart = useCallback(() => {
    const trimmed = name.trim() || 'Untitled entry';
    // Cleared up front, not after the save: anything typed while the save is in
    // flight would otherwise be wiped when the reset landed.
    setName('');

    void (async () => {
      // Best-effort: a failure sweeping the previously-running entries must
      // not stop the new one from starting. The sweep reads the collection,
      // which may have been invalidated under us; losing the auto-stop is a
      // far smaller problem than silently dropping the entry the user asked
      // for.
      if (exclusive) {
        try {
          const members = await collection.getAllMembers();
          const stamp = Date.now();

          for (const subject of members) {
            const row = store.getResourceLoading(subject);
            const start = row.get(startProp.subject);
            const end = row.get(endProp.subject);

            if (typeof start === 'number' && typeof end !== 'number') {
              await row.set(endProp.subject, stamp, false);
              await row.save();
            }
          }
        } catch {
          // ignored on purpose — see above
        }
      }

      const propVals: Record<string, JSONValue> = {
        [core.properties.name]: trimmed,
        // Required for the row to show up in the table's collection.
        [commits.properties.createdAt]: Date.now(),
        [startProp.subject]: Date.now(),
      };

      const row = await store.newResource({
        parent: tableSubject,
        isA: tableClass.subject,
        propVals,
      });
      await row.save();
      store.notifyResourceManuallyCreated(row);
      // The grid freezes its member count at first load and renders anything
      // past it as a session draft, so a new row is invisible until the count
      // is bumped.
      onEntryCreated();
    })().catch(e => {
      // Never silent: a swallowed failure here looks exactly like "the button
      // does nothing", which is precisely how this went unnoticed before.
      console.error('Failed to start a timer entry', e);
      toast.error('Could not start the entry');
    });
  }, [
    name,
    exclusive,
    collection,
    store,
    startProp,
    endProp,
    tableSubject,
    tableClass,
    onEntryCreated,
  ]);

  return (
    <Bar>
      <NameInput
        placeholder='What are you working on?'
        data-testid='timer-new-input'
        value={name}
        onChange={e => setName(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter') {
            e.preventDefault();
            handleStart();
          }
        }}
      />
      <Button data-testid='timer-start-new' onClick={handleStart}>
        <FaPlay /> <span>Start</span>
      </Button>
      <Toggle title='Stop the running entry when another starts'>
        <Checkbox
          checked={exclusive}
          onChange={setExclusive}
          data-testid='timer-exclusive'
        />
        <span>One at a time</span>
      </Toggle>
    </Bar>
  );
}

const Bar = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding-block: 0.5rem;
  flex-wrap: wrap;
`;

const NameInput = styled(InputStyled)`
  flex: 1;
  min-width: 12rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
  padding-inline: 0.6rem;
`;

const Toggle = styled.label`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85em;
  white-space: nowrap;
  cursor: pointer;
`;
