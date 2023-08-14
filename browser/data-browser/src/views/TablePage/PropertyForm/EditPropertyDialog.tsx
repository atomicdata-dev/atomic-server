import { Resource, properties, useStore, useString } from '@tomic/react';
import React, { useCallback, useEffect, useState } from 'react';
import { PropertyForm, getCategoryFromDatatype } from './PropertyForm';
import { FormValidationContextProvider } from '../../../components/forms/formValidation/FormValidationContextProvider';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../../components/Dialog';
import { Button } from '../../../components/Button';

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
  const store = useStore();
  const [valid, setValid] = useState(true);

  const [datatype] = useString(resource, properties.datatype);

  const category = getCategoryFromDatatype(datatype);

  const onSuccess = useCallback(() => {
    resource.save(store);
  }, [resource]);

  const [dialogProps, show, hide] = useDialog({ bindShow, onSuccess });

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
          <PropertyForm
            resource={resource}
            category={category}
            onSubmit={handleSaveClick}
          />
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
