import { useEffect, useState } from 'react';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../Dialog';
import { ParentPicker } from './ParentPicker';
import { Button } from '../Button';
import { waitForActiveDocument } from '../Dialog/waitForActiveDocument';

interface ParentPickerDialogProps {
  root?: string;
  open: boolean;
  onSelect: (subject: string) => void;
  onCancel?: () => void;
  onOpenChange?: (open: boolean) => void;
  title?: string;
}

export function ParentPickerDialog({
  open,
  root,
  title,
  onSelect,
  onCancel,
  onOpenChange,
}: ParentPickerDialogProps): React.JSX.Element {
  const [selected, setSelected] = useState<string>();

  const { dialogProps, show, close, isOpen } = useDialog({
    onCancel,
    bindShow: onOpenChange,
  });

  const select = () => {
    if (!selected) return;

    waitForActiveDocument(() => {
      onSelect(selected);
    });
    close(true);
  };

  useEffect(() => {
    if (open) {
      show();
    } else {
      close();
      setSelected(undefined);
    }
  }, [open]);

  return (
    <Dialog {...dialogProps}>
      {isOpen && (
        <>
          <DialogTitle>
            <h1>{title ?? 'Select a location'}</h1>
          </DialogTitle>
          <DialogContent>
            <ParentPicker root={root} value={selected} onChange={setSelected} />
          </DialogContent>
          <DialogActions>
            <Button subtle onClick={() => close(false)}>
              Cancel
            </Button>
            <Button onClick={select} disabled={!selected}>
              Select
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );
}
