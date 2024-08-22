import { Datatype, Resource, useStore, validateDatatype } from '@tomic/react';
import { useRef, useState } from 'react';
import { FaPlus } from 'react-icons/fa';
import { styled } from 'styled-components';
import { transition } from '../../helpers/transition';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../components/Dialog';
import { Button } from '../../components/Button';
import { InputStyled, InputWrapper } from '../../components/forms/InputStyles';
import { stringToSlug } from '../../helpers/stringToSlug';
import { Column } from '../../components/Row';
import { newClass, subjectForClass } from './newClass';
import { toAnchorId } from './toAnchorId';

interface NewClassButtonProps {
  resource: Resource;
}

export function NewClassButton({ resource }: NewClassButtonProps): JSX.Element {
  const store = useStore();
  const [inputValue, setInputValue] = useState('');
  const [isValid, setIsValid] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const subject = subjectForClass(resource, inputValue);

  const {
    dialogProps,
    show,
    close: hide,
    isOpen,
  } = useDialog({
    onSuccess: async () => {
      const createdClass = await newClass(inputValue, resource, store);
      const id = toAnchorId(createdClass);
      document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
    },
  });

  const handleShortNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const slugValue = stringToSlug(e.target.value);
    setInputValue(slugValue);
    validate(slugValue);
  };

  const validate = (value: string) => {
    if (!value) {
      setIsValid(false);

      return;
    }

    try {
      validateDatatype(value, Datatype.SLUG);
      setIsValid(true);
    } catch (e) {
      setIsValid(false);
    }
  };

  const openAndReset = () => {
    setInputValue('');
    setIsValid(false);
    show();

    requestAnimationFrame(() => {
      inputRef.current?.focus();
    });
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      hide(false);
    }

    if (e.key === 'Enter' && isValid) {
      hide(true);
    }
  };

  return (
    <>
      <DashedButton onClick={openAndReset}>
        <FaPlus /> Add class
      </DashedButton>
      <Dialog {...dialogProps}>
        {isOpen && (
          <>
            <DialogTitle>
              <h1>New Class</h1>
            </DialogTitle>
            <DialogContent>
              <Column>
                <InputWrapper>
                  <InputStyled
                    ref={inputRef}
                    placeholder='shortname'
                    value={inputValue}
                    onChange={handleShortNameChange}
                    onKeyDown={handleKeyDown}
                  />
                </InputWrapper>

                <SubjectWrapper key={0}>{subject}</SubjectWrapper>
              </Column>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => hide(false)} subtle>
                Cancel
              </Button>
              <Button onClick={() => hide(true)} disabled={!isValid}>
                Save
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </>
  );
}

const DashedButton = styled.button`
  width: 100%;
  height: 20rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 1ch;
  appearance: none;
  background: none;
  border: 2px dashed ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
  &:hover,
  &:focus-visible {
    background: ${p => p.theme.colors.bg};
    border-color: ${p => p.theme.colors.main};
    color: ${p => p.theme.colors.main};
  }
  ${transition('background', 'color', 'border-color')}
`;

const SubjectWrapper = styled.div`
  width: 100%;
  max-width: 60ch;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  color: ${p => p.theme.colors.textLight};
  background-color: ${p => p.theme.colors.bg1};
  padding-inline: 0.5rem;
  padding-block: 0.2rem;
  border-radius: ${p => p.theme.radius};
`;
