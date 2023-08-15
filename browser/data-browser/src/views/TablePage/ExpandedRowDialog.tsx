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
import { Title } from '../../components/Title';

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
        <Title resource={resource} link />
      </DialogTitle>
      <DialogContent>
        <AllProps editable columns resource={resource} />
      </DialogContent>
    </Dialog>
  );
}
