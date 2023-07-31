import React, { useEffect, useState } from 'react';
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
import { ErrorLook } from '../../../components/ErrorLook';

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
  const [error, setError] = useState<Error | undefined>();

  const [recommends, setRecommends] = useArray(
    tableClassResource,
    urls.properties.recommends,
    { commit: true },
  );
  const [dialogProps, show, hide] = useDialog({ bindShow });

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
      <DialogTitle>
        <h1>Add external property</h1>
      </DialogTitle>
      <DialogContent>
        <ResourceSelector
          hideCreateOption
          setSubject={setSubject}
          value={subject}
          onValidate={setError}
          classType={urls.classes.property}
        />
        {error && <ErrorLook>{error.message}</ErrorLook>}
      </DialogContent>
      <DialogActions>
        <Button subtle onClick={() => hide()}>
          Cancel
        </Button>
        <Button disabled={!subject || !!error} onClick={onAddClick}>
          Add
        </Button>
      </DialogActions>
    </Dialog>
  );
}
