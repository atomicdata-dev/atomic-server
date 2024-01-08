import { useResource, Core, dataBrowser, core, useStore } from '@tomic/react';
import { useState, useCallback, useEffect, FormEvent, FC } from 'react';
import styled from 'styled-components';
import { stringToSlug } from '../../../../../helpers/stringToSlug';
import { BetaBadge } from '../../../../BetaBadge';
import { Button } from '../../../../Button';
import {
  useDialog,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
} from '../../../../Dialog';
import Field from '../../../Field';
import { InputWrapper, InputStyled } from '../../../InputStyles';
import type { CustomResourceDialogProps } from '../../useNewResourceUI';
import { useCreateAndNavigate } from '../../../../../hooks/useCreateAndNavigate';

const instanceOpts = {
  newResource: true,
};

export const NewTableDialog: FC<CustomResourceDialogProps> = ({
  parent,
  onClose,
}) => {
  const store = useStore();
  const [instanceSubject] = useState(() => store.createSubject('class'));
  const instanceResource = useResource<Core.Class>(
    instanceSubject,
    instanceOpts,
  );

  const [name, setName] = useState('');

  const createResourceAndNavigate = useCreateAndNavigate();

  const onCancel = useCallback(() => {
    instanceResource.destroy(store);
    onClose();
  }, [onClose, instanceResource, store]);

  const onSuccess = useCallback(async () => {
    await instanceResource.set(
      core.properties.shortname,
      stringToSlug(name),
      store,
    );
    await instanceResource.set(
      core.properties.description,
      `Represents a row in the ${name} table`,
      store,
    );
    await instanceResource.set(
      core.properties.isA,
      [core.classes.class],
      store,
    );
    await instanceResource.set(core.properties.parent, parent, store);
    await instanceResource.set(
      core.properties.recommends,
      [core.properties.name],
      store,
    );
    await instanceResource.save(store);

    createResourceAndNavigate(
      dataBrowser.classes.table,
      {
        [core.properties.name]: name,
        [core.properties.classtype]: instanceResource.getSubject(),
      },
      parent,
    );

    onClose();
  }, [name, instanceResource, store, onClose, parent]);

  const [dialogProps, show, hide] = useDialog({ onCancel, onSuccess });

  useEffect(() => {
    show();
  }, []);

  return (
    <Dialog {...dialogProps}>
      <RelativeDialogTitle>
        <h1>New Table</h1>
        <BetaBadge />
      </RelativeDialogTitle>
      <WiderDialogContent>
        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            hide(true);
          }}
        >
          <Field required label='Name'>
            <InputWrapper>
              <InputStyled
                placeholder='New Table'
                value={name}
                autoFocus={true}
                onChange={e => setName(e.target.value)}
              />
            </InputWrapper>
          </Field>
        </form>
      </WiderDialogContent>
      <DialogActions>
        <Button onClick={() => hide(false)} subtle>
          Cancel
        </Button>
        <Button onClick={() => hide(true)} disabled={name.trim() === ''}>
          Create
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const WiderDialogContent = styled(DialogContent)`
  width: min(80vw, 20rem);
`;

const RelativeDialogTitle = styled(DialogTitle)`
  display: flex;
  align-items: flex-start;
  gap: 1ch;
`;
