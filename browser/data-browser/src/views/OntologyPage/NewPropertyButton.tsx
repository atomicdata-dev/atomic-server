import {
  Datatype,
  Resource,
  useStore,
  validateDatatype,
  type Core,
} from '@tomic/react';
import { useRef, useState, type JSX } from 'react';
import { FaPlus } from 'react-icons/fa6';
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
import { newProperty } from './ontologyUtils';
import { toAnchorId } from '../../helpers/toAnchorId';
import { DashedButton } from './DashedButton';
import { useOntologyContext } from './OntologyContext';

interface NewPropertyButtonProps {
  parent: Resource<Core.Ontology>;
}

export function NewPropertyButton({
  parent,
}: NewPropertyButtonProps): JSX.Element {
  const store = useStore();
  const [inputValue, setInputValue] = useState('');
  const [isValid, setIsValid] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const { addProperty } = useOntologyContext();

  const [dialogProps, show, hide, isOpen] = useDialog({
    onSuccess: async () => {
      const createdProperty = await newProperty(inputValue, parent, store);
      await addProperty(createdProperty);
      requestAnimationFrame(() => {
        const id = toAnchorId(createdProperty);
        document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
      });
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
        <FaPlus /> <span>Add property</span>
      </DashedButton>
      <Dialog {...dialogProps}>
        {isOpen && (
          <>
            <DialogTitle>
              <h1>New Property</h1>
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
