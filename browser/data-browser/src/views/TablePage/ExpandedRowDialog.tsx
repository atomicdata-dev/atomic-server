import { useResource } from '@tomic/react';
import React, { useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../components/Dialog';
import AllProps from '../../components/AllProps';
import { useTableEditorContext } from '../../components/TableEditor/TableEditorContext';

interface ExpandedRowDialogProps {
  subject: string;
  open: boolean;
  bindOpen: (open: boolean) => void;
}

export function ExpandedRowDialog({
  subject,
  open,
  bindOpen,
}: ExpandedRowDialogProps): JSX.Element {
  const { tableRef } = useTableEditorContext();
  const resource = useResource(subject);
  const [dialogProps, show] = useDialog({
    bindShow: bindOpen,
    triggerRef: tableRef,
  });

  useEffect(() => {
    if (open) {
      show();
    }
  }, [open, show]);

  return (
    <Dialog {...dialogProps}>
      <DialogTitle>
        <h1>{resource.title}</h1>
      </DialogTitle>
      <DialogContent>
        <AllProps editable columns resource={resource} />
      </DialogContent>
    </Dialog>
  );
}
