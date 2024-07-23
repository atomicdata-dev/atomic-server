import { dataBrowser, core, useStore } from '@tomic/react';
import { useState, useCallback, useEffect, FormEvent, FC } from 'react';
import { styled } from 'styled-components';
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
import { ResourceSelector } from '../../../ResourceSelector';
import { Checkbox, CheckboxLabel } from '../../../Checkbox';
import { useAddToOntology } from '../../../../../hooks/useAddToOntology';

interface NewTableDialogProps extends CustomResourceDialogProps {
  initialExistingClass?: string;
}

export const NewTableDialog: FC<NewTableDialogProps> = ({
  parent,
  initialExistingClass,
  onClose,
}) => {
  const store = useStore();
  const [useExistingClass, setUseExistingClass] =
    useState(!!initialExistingClass);
  const [existingClass, setExistingClass] = useState<string | undefined>(
    initialExistingClass,
  );
  const [name, setName] = useState('');

  const addToOntology = useAddToOntology();
  const createResourceAndNavigate = useCreateAndNavigate();

  const onCancel = useCallback(() => {
    onClose();
  }, [onClose]);

  const onSuccess = useCallback(async () => {
    let classSubject: string;

    if (!useExistingClass) {
      const instanceResource = await store.newResource({
        isA: core.classes.class,
        propVals: {
          [core.properties.shortname]: stringToSlug(name),
          [core.properties.description]:
            `Represents a row in the ${name} table`,
          [core.properties.recommends]: [core.properties.name],
        },
      });

      await addToOntology(instanceResource);
      classSubject = instanceResource.subject;
    } else {
      if (existingClass === undefined) {
        throw new Error('Existing class is undefined');
      }

      classSubject = existingClass;
    }

    createResourceAndNavigate(
      dataBrowser.classes.table,
      {
        [core.properties.name]: name,
        [core.properties.classtype]: classSubject,
      },
      {
        parent,
      },
    );

    onClose();
  }, [
    name,
    onClose,
    parent,
    useExistingClass,
    existingClass,
    addToOntology,
    createResourceAndNavigate,
  ]);

  const {
    dialogProps,
    show,
    close: hide,
    isOpen,
  } = useDialog({ onCancel, onSuccess });

  useEffect(() => {
    show();
  }, []);

  const hasName = name.trim() !== '';
  const saveDisabled = useExistingClass ? !hasName || !existingClass : !hasName;

  return (
    <Dialog {...dialogProps}>
      {isOpen && (
        <>
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
              <CheckboxLabel>
                <Checkbox
                  checked={useExistingClass}
                  onChange={setUseExistingClass}
                />
                Use existing class
              </CheckboxLabel>
              <Field>
                {useExistingClass && (
                  <ResourceSelector
                    hideCreateOption
                    disabled={!useExistingClass}
                    isA={core.classes.class}
                    setSubject={setExistingClass}
                    value={existingClass}
                  />
                )}
              </Field>
            </form>
          </WiderDialogContent>
          <DialogActions>
            <Button onClick={() => hide(false)} subtle>
              Cancel
            </Button>
            <Button onClick={() => hide(true)} disabled={saveDisabled}>
              Create
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );
};

const WiderDialogContent = styled(DialogContent)`
  /* width: min(80vw, 20rem); */
`;

const RelativeDialogTitle = styled(DialogTitle)`
  display: flex;
  align-items: flex-start;
  gap: 1ch;
`;
