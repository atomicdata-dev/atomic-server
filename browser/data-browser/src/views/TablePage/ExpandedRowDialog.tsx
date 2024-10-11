import { commits, core, useResource, dataBrowser } from '@tomic/react';
import { useEffect } from 'react';
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

const EXCLUDED_PROPS = [
  commits.properties.lastCommit,
  core.properties.parent,
  core.properties.isA,
  dataBrowser.properties.subResources,
];

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
        <AllProps
          editable
          columns
          resource={resource}
          except={EXCLUDED_PROPS}
        />
      </DialogContent>
    </Dialog>
  );
}
