import toast from 'react-hot-toast';
import type { Property, Resource } from '@tomic/react';
import { FaFloppyDisk } from 'react-icons/fa6';
import { Button } from '../../Button';
import { Column, Row } from '../../Row';
import { ErrMessage } from '../InputStyles';
import InputSwitcher from '../InputSwitcher';
import { useEffect, useState } from 'react';

interface ValueFormEditProps {
  resource: Resource;
  property: Property;
  onClose: () => void;
}

export function ValueFormEdit({
  resource,
  property,
  onClose,
}: ValueFormEditProps): React.JSX.Element {
  const [err, setErr] = useState<Error | undefined>(undefined);

  const save = async () => {
    try {
      await resource.save();
      onClose();
      toast.success('Resource saved');
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
    // Refresh the data when the edit form closes.
    return () => {
      resource.refresh();
    };
  }, []);

  return (
    <Column gap='0.5rem'>
      <InputSwitcher
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
        <Button onClick={save}>
          <FaFloppyDisk />
          Save
        </Button>
      </Row>
    </Column>
  );
}
