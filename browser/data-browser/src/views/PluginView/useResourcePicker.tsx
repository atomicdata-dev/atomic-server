import { Button } from '@components/Button';
import { useDialog, Dialog } from '@components/Dialog';
import { SearchBox } from '@components/forms/SearchBox';
import type { PickResourceArgs } from '@tomic/plugin';
import { useState, useRef, useEffect } from 'react';
import { styled } from 'styled-components';
import { useStoredPluginGrants } from './useStoredPluginGrants';

export type PickResourceFn = (
  args?: PickResourceArgs,
) => Promise<string | undefined>;

export function useResourcePicker(
  plugin: string,
): [PickResourceFn, React.ReactNode] {
  const [selectedResource, setSelectedResource] = useState<string | undefined>(
    undefined,
  );
  const resolverRef = useRef<((value: string | undefined) => void) | undefined>(
    undefined,
  );

  useEffect(
    () => () => {
      resolverRef.current?.(undefined);
      resolverRef.current = undefined;
    },
    [],
  );

  const [args, setArgs] = useState<PickResourceArgs>({});

  const { addGrant } = useStoredPluginGrants(plugin, 'read');

  const reset = () => {
    setArgs({});
    resolverRef.current = undefined;
    setSelectedResource(undefined);
  };

  const [dialogProps, show, close] = useDialog({
    onSuccess: () => {
      if (!selectedResource) {
        reset();

        return;
      }

      resolverRef.current?.(selectedResource);
      addGrant(selectedResource);
      reset();
    },
    onCancel: () => {
      resolverRef.current?.(undefined);
      reset();
    },
  });

  const pickResource = (pickArgs: PickResourceArgs = {}) => {
    setArgs(pickArgs);

    return new Promise<string | undefined>(resolve => {
      resolverRef.current = resolve;
      show();
    });
  };

  const dialog = (
    <Dialog {...dialogProps}>
      <Dialog.Title>
        <h1>{args.title ?? 'Pick Resource'}</h1>
      </Dialog.Title>
      <Dialog.Content>
        <Wrapper>
          {args.message && <p>{args.message}</p>}
          <SearchBox
            value={selectedResource}
            onChange={setSelectedResource}
            isA={args.isA}
            scopes={args.scope ? [args.scope] : undefined}
          />
        </Wrapper>
      </Dialog.Content>
      <Dialog.Actions>
        <Button subtle onClick={() => close(false)}>
          Cancel
        </Button>
        <Button onClick={() => close(true)}>Confirm</Button>
      </Dialog.Actions>
    </Dialog>
  );

  return [pickResource, dialog];
}

const Wrapper = styled.div`
  padding: 2px;
`;
