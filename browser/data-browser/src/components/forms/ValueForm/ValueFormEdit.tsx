import toast from 'react-hot-toast';
import type { Property, Resource } from '@tomic/react';
import { FaFloppyDisk } from 'react-icons/fa6';
import { Button } from '../../Button';
import { Column, Row } from '../../Row';
import { ErrMessage } from '../InputStyles';
import InputSwitcher from '../InputSwitcher';
import { useEffect, useRef, useState } from 'react';
import { discardEdit } from '../../../helpers/discardEdit';
import { FormValidationContextProvider } from '../formValidation/FormValidationContextProvider';

interface ValueFormEditProps {
  resource: Resource;
  property: Property;
  onClose: () => void;
  /** Lets a label outside the form name the input. */
  inputId?: string;
}

export function ValueFormEdit({
  resource,
  property,
  onClose,
  inputId,
}: ValueFormEditProps): React.JSX.Element {
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [isFormValid, setIsFormValid] = useState(false);
  // What the property held when editing started. The inputs write to the
  // resource as you type, so closing without saving has to put this back, or
  // the next save of any other property would persist the discarded edit.
  const [initialValue] = useState(() => resource.get(property.subject));
  const saved = useRef(false);

  const save = async () => {
    try {
      await resource.save();
      saved.current = true;
      onClose();
    } catch (e) {
      setErr(e);
      toast.error('Could not save resource...');
    }
  };

  const cancel = () => {
    setErr(undefined);
    onClose();
  };

  useEffect(() => {
    // Refresh the data when the edit form closes. Closing in any way other than
    // saving (Cancel, Escape) discards what was typed.
    return () => {
      if (!saved.current) {
        discardEdit(resource, property.subject, initialValue);
      }

      resource.refresh();
    };
  }, []);

  return (
    <FormValidationContextProvider onValidationChange={setIsFormValid}>
      <Column gap='0.5rem'>
        <InputSwitcher
          id={inputId}
          data-test={`input-${property.subject}`}
          resource={resource}
          property={property}
          autoFocus
        />
        {err && <ErrMessage>{err.message}</ErrMessage>}
        <Row gap='0.5rem'>
          <Button subtle onClick={cancel}>
            Cancel
          </Button>
          <Button onClick={save} disabled={!isFormValid}>
            <FaFloppyDisk />
            <span>Save</span>
          </Button>
        </Row>
      </Column>
    </FormValidationContextProvider>
  );
}
