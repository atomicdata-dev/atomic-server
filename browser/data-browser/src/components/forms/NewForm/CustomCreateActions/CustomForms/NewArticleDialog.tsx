import { validateDatatype, Datatype, core, dataBrowser } from '@tomic/react';
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

export const NewArticleDialog: FC<CustomResourceDialogProps> = ({
  parent,
  onClose,
}) => {
  const [name, setName] = useState('');
  const [valid, setValid] = useState(false);

  const createResourceAndNavigate = useCreateAndNavigate();

  const onSuccess = useCallback(async () => {
    const shortName = stringToSlug(name);

    const subject = `${parent}/${shortName}`;

    // TODO: make subject and stuff.
    createResourceAndNavigate(
      dataBrowser.classes.article,
      {
        [core.properties.name]: name,
        [core.properties.description]: '',
      },
      {
        parent,
        subject,
      },
    );

    onClose();
  }, [name, createResourceAndNavigate, onClose, parent]);

  const { dialogProps, show, close } = useDialog({
    onSuccess,
    onCancel: onClose,
  });

  const onNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setName(e.target.value);
    const value = stringToSlug(e.target.value);

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
      <H1>New Article</H1>
      <DialogContent>
        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            close(true);
          }}
        >
          <Field required label='Title'>
            <InputWrapper>
              <InputStyled
                placeholder='New Article'
                value={name}
                autoFocus={true}
                onChange={onNameChange}
              />
            </InputWrapper>
          </Field>
          <Explanation>
            Title is used to construct the subject, keep in mind that the
            subject cannot be changed later.
          </Explanation>
        </form>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => close(false)} subtle>
          Cancel
        </Button>
        <Button onClick={() => close(true)} disabled={!valid}>
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
