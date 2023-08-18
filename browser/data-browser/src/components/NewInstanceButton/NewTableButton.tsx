import {
  classes,
  properties,
  useResource,
  useStore,
  useTitle,
} from '@tomic/react';
import React, { FormEvent, useCallback, useState } from 'react';
import { Button } from '../Button';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../Dialog';
import Field from '../forms/Field';
import { InputStyled, InputWrapper } from '../forms/InputStyles';
import { Base } from './Base';
import { useCreateAndNavigate } from './useCreateAndNavigate';
import { NewInstanceButtonProps } from './NewInstanceButtonProps';
import { stringToSlug } from '../../helpers/stringToSlug';
import { styled } from 'styled-components';
import { BetaBadge } from '../BetaBadge';

const instanceOpts = {
  newResource: true,
};

export function NewTableButton({
  klass,
  subtle,
  icon,
  IconComponent,
  parent,
  children,
  label,
}: NewInstanceButtonProps): JSX.Element {
  const store = useStore();
  const resource = useResource(klass);
  const [instanceSubject] = useState(() => store.createSubject('class'));
  const instanceResource = useResource(instanceSubject, instanceOpts);

  const [title] = useTitle(resource);
  const [name, setName] = useState('');

  const createResourceAndNavigate = useCreateAndNavigate(klass, parent);

  const onCancel = useCallback(() => {
    instanceResource.destroy(store);
  }, []);

  const onSuccess = useCallback(async () => {
    await instanceResource.set(properties.shortname, stringToSlug(name), store);
    await instanceResource.set(
      properties.description,
      `Represents a row in the ${name} table`,
      store,
    );
    await instanceResource.set(properties.isA, [classes.class], store);
    await instanceResource.set(properties.parent, parent, store);
    await instanceResource.set(properties.recommends, [properties.name], store);
    await instanceResource.save(store);

    createResourceAndNavigate('table', {
      [properties.name]: name,
      [properties.classType]: instanceResource.getSubject(),
      [properties.isA]: [classes.table],
    });
  }, [name, instanceResource]);

  const [dialogProps, show, hide] = useDialog({ onCancel, onSuccess });

  return (
    <>
      <Base
        onClick={show}
        title={title}
        icon={icon}
        IconComponent={IconComponent}
        subtle={subtle}
        label={label}
      >
        {children}
      </Base>
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
    </>
  );
}

const WiderDialogContent = styled(DialogContent)`
  width: min(80vw, 20rem);
`;

const RelativeDialogTitle = styled(DialogTitle)`
  display: flex;
  align-items: flex-start;
  gap: 1ch;
`;
