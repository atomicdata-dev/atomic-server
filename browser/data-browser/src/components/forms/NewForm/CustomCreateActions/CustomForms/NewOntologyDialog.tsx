import { validateDatatype, Datatype, core } from '@tomic/react';
import { useState, useCallback, FormEvent, FC, useEffect } from 'react';
import { styled } from 'styled-components';
import { stringToSlug } from '../../../../../helpers/stringToSlug';
import { Button } from '../../../../Button';
import {
  useDialog,
  Dialog,
  DialogContent,
  DialogActions,
} from '../../../../Dialog';
import Field from '../../../Field';
import { InputWrapper, InputStyled } from '../../../InputStyles';
import { CustomResourceDialogProps } from '../../useNewResourceUI';
import { useCreateAndNavigate } from '../../../../../hooks/useCreateAndNavigate';

export const NewOntologyDialog: FC<CustomResourceDialogProps> = ({
  parent,
  onClose,
}) => {
  const [shortname, setShortname] = useState('');
  const [valid, setValid] = useState(false);

  const createResourceAndNavigate = useCreateAndNavigate();

  const onSuccess = useCallback(async () => {
    createResourceAndNavigate(
      core.classes.ontology,
      {
        [core.properties.shortname]: shortname,
        [core.properties.description]: 'description',
        [core.properties.classes]: [],
        [core.properties.properties]: [],
        [core.properties.instances]: [],
      },
      {
        parent,
      },
    );

    onClose();
  }, [shortname, createResourceAndNavigate, onClose, parent]);

  const {
    dialogProps,
    show,
    close: hide,
  } = useDialog({ onSuccess, onCancel: onClose });

  const onShortnameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = stringToSlug(e.target.value);
    setShortname(value);

    try {
      validateDatatype(value, Datatype.SLUG);
      setValid(true);
    } catch (_) {
      setValid(false);
    }
  };

  useEffect(() => {
    show();
  }, []);

  return (
    <Dialog {...dialogProps}>
      <H1>New Ontology</H1>
      <DialogContent>
        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            hide(true);
          }}
        >
          <Explanation>
            An ontology is a collection of classes and properties that together
            describe a concept. Great for data models.
          </Explanation>
          <Field required label='Shortname'>
            <InputWrapper>
              <InputStyled
                placeholder='my-ontology'
                value={shortname}
                autoFocus={true}
                onChange={onShortnameChange}
              />
            </InputWrapper>
          </Field>
        </form>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => hide(false)} subtle>
          Cancel
        </Button>
        <Button onClick={() => hide(true)} disabled={!valid}>
          Create
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const H1 = styled.h1`
  margin: 0;
`;

const Explanation = styled.p`
  color: ${p => p.theme.colors.textLight};
  max-width: 60ch;
`;
