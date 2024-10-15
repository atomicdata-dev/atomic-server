import { unknownSubject, useResource, useTitle } from '@tomic/react';
import { useCallback, useEffect, useState } from 'react';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../Dialog';
import { ResourceForm, ResourceFormVariant } from './ResourceForm';
import { Button } from '../Button';
import { InlineErrMessage } from './InputStyles';
import { useSaveResource } from './hooks/useSaveResource';

interface EditFormDialogProps {
  subject: string;
  show: boolean;
  bindShow: (show: boolean) => void;
}

export function EditFormDialog({
  subject,
  show,
  bindShow,
}: EditFormDialogProps) {
  const [dialogProps, showDialog, hideDialog, dialogVisible] = useDialog({
    bindShow,
  });
  const resource = useResource(subject ?? unknownSubject);
  const [title] = useTitle(resource);

  const [isFormValid, setIsFormValid] = useState(false);

  const handleValidationChange = useCallback((valid: boolean) => {
    setIsFormValid(valid);
  }, []);

  const onSave = useCallback(() => {
    hideDialog(true);
  }, [hideDialog]);

  const [save, saving, error] = useSaveResource(resource, onSave);

  useEffect(() => {
    if (show) {
      showDialog();
    } else {
      hideDialog();
    }
  }, [show, showDialog, hideDialog]);

  return (
    <Dialog {...dialogProps} width='80ch'>
      {dialogVisible && (
        <>
          <DialogTitle>
            <h1>Edit {title}</h1>
          </DialogTitle>
          <DialogContent>
            <ResourceForm
              resource={resource}
              variant={ResourceFormVariant.Dialog}
              onValidationChange={handleValidationChange}
            />
          </DialogContent>
          <DialogActions>
            {error && <InlineErrMessage>{error.message}</InlineErrMessage>}
            <Button subtle onClick={() => hideDialog(false)}>
              Cancel
            </Button>
            <Button onClick={save} disabled={saving || !isFormValid}>
              Save
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );
}
