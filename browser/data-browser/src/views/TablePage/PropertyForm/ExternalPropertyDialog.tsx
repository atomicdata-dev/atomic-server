import { useEffect, useState } from 'react';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../../components/Dialog';
import { ResourceSelector } from '../../../components/forms/ResourceSelector';
import { Resource, urls, useArray } from '@tomic/react';
import { Button } from '../../../components/Button';
import { FormValidationContextProvider } from '../../../components/forms/formValidation/FormValidationContextProvider';

interface ExternalPropertyDialogProps {
  open: boolean;
  bindShow: React.Dispatch<boolean>;
  tableClassResource: Resource;
}

export function ExternalPropertyDialog({
  open,
  bindShow,
  tableClassResource,
}: ExternalPropertyDialogProps): JSX.Element {
  const [subject, setSubject] = useState<string | undefined>();
  const [isValid, setIsValid] = useState(false);

  const [recommends, setRecommends] = useArray(
    tableClassResource,
    urls.properties.recommends,
    { commit: true },
  );
  const { dialogProps, show, close: hide } = useDialog({ bindShow });

  const onAddClick = () => {
    if (subject) {
      setRecommends([...recommends, subject]);
      hide();
    }
  };

  useEffect(() => {
    if (open) {
      show();
      setSubject(undefined);
    }
  }, [open, show]);

  return (
    <Dialog {...dialogProps}>
      <FormValidationContextProvider onValidationChange={setIsValid}>
        <DialogTitle>
          <h1>Add external property</h1>
        </DialogTitle>
        <DialogContent>
          <ResourceSelector
            required
            hideCreateOption
            setSubject={setSubject}
            value={subject}
            isA={urls.classes.property}
          />
        </DialogContent>
        <DialogActions>
          <Button subtle onClick={() => hide()}>
            Cancel
          </Button>
          <Button disabled={!isValid} onClick={onAddClick}>
            Add
          </Button>
        </DialogActions>
      </FormValidationContextProvider>
    </Dialog>
  );
}
