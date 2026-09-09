import { Resource } from '@tomic/react';
import { useCallback, useEffect, useState, type JSX } from 'react';
import { PropertyForm } from './PropertyForm';
import { FormValidationContextProvider } from '@components/forms/formValidation/FormValidationContextProvider';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '@components/Dialog';
import { Button } from '@components/Button';
import { getCategoryFromResource } from './categories';

interface EditPropertyDialogProps {
  resource: Resource;
  showDialog: boolean;
  bindShow: React.Dispatch<boolean>;
}

export function EditPropertyDialog({
  resource,
  showDialog,
  bindShow,
}: EditPropertyDialogProps): JSX.Element {
  const [valid, setValid] = useState(true);

  const category = getCategoryFromResource(resource);

  const onSuccess = useCallback(() => {
    resource.save().catch(err => {
      console.error('Failed to save property', err);
    });
  }, [resource]);

  const [dialogProps, show, hide, visible] = useDialog({ bindShow, onSuccess });

  useEffect(() => {
    if (showDialog) {
      show();
    } else {
      hide();
    }
  }, [showDialog]);

  const handleSaveClick = useCallback(() => {
    hide(true);
  }, [hide]);

  return (
    <FormValidationContextProvider onValidationChange={setValid}>
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>Edit Column</h1>
        </DialogTitle>
        <DialogContent>
          {visible && (
            <PropertyForm
              existingProperty
              resource={resource}
              category={category}
              onSubmit={handleSaveClick}
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleSaveClick} disabled={!valid}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </FormValidationContextProvider>
  );
}
