import { collections, core } from '@tomic/react';
import { useState, useCallback, FormEvent, useEffect, FC } from 'react';
import { Button } from '../../../../Button';
import {
  useDialog,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '../../../../Dialog';
import Field from '../../../Field';
import { InputWrapper, InputStyled } from '../../../InputStyles';
import { CustomResourceDialogProps } from '../../useNewResourceUI';
import { useCreateAndNavigate } from '../../../../../hooks/useCreateAndNavigate';
import { ResourceSelector } from '../../../ResourceSelector';

export const NewCollectionDialog: FC<CustomResourceDialogProps> = ({
  parent,
  onClose,
}) => {
  const [name, setName] = useState('New Collection');
  const [valueFilter, setValue] = useState<string | undefined>();
  const [propertyFilter, setProperty] = useState<string | undefined>();

  const { dialogProps, show, close } = useDialog({ onCancel: onClose });

  const createResourceAndNavigate = useCreateAndNavigate();

  const onDone = useCallback(
    (e: FormEvent) => {
      e.preventDefault();

      createResourceAndNavigate(
        collections.classes.collection,
        {
          [core.properties.name]: name,
          [collections.properties.value]: valueFilter,
          [collections.properties.property]: propertyFilter,
          [collections.properties.pageSize]: 30,
          [collections.properties.currentPage]: 0,
        },
        {
          parent,
        },
      );

      onClose();
    },
    [valueFilter, onClose, propertyFilter],
  );

  useEffect(() => {
    show();
  }, []);

  return (
    <Dialog {...dialogProps}>
      <DialogTitle>
        <h1>New Collection</h1>
      </DialogTitle>
      <DialogContent>
        <form onSubmit={onDone}>
          <Field required label='name'>
            <InputWrapper>
              <InputStyled
                placeholder='Name your Collection'
                value={name}
                autoFocus={true}
                onChange={e => setName(e.target.value)}
              />
            </InputWrapper>
          </Field>
          <Field label='property'>
            <div>
              <ResourceSelector
                isA={core.classes.property}
                setSubject={setProperty}
                value={propertyFilter}
              />
            </div>
          </Field>
          <Field label='value'>
            <InputWrapper>
              <InputStyled
                placeholder='Set a value filter (optional)'
                value={valueFilter}
                onChange={e => setValue(e.target.value)}
              />
            </InputWrapper>
          </Field>
        </form>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => close(false)} subtle>
          Cancel
        </Button>
        <Button onClick={onDone} disabled={!propertyFilter && !valueFilter}>
          Ok
        </Button>
      </DialogActions>
    </Dialog>
  );
};
