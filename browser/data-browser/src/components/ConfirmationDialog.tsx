import { useEffect } from 'react';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from './Dialog';
import { Button } from './Button';

export enum ConfirmationDialogTheme {
  Default = 'default',
  Alert = 'alert',
}

interface ConfirmationDialogProps {
  title: string;
  confirmLabel?: string;
  onConfirm?: () => void;
  onCancel?: () => void;
  theme?: ConfirmationDialogTheme;
  show: boolean;
  bindShow?: (show: boolean) => void;
}

export function ConfirmationDialog({
  title,
  confirmLabel = 'Confirm',
  onConfirm,
  onCancel,
  children,
  show,
  bindShow,
  theme = ConfirmationDialogTheme.Default,
}: React.PropsWithChildren<ConfirmationDialogProps>): JSX.Element {
  const {
    dialogProps,
    show: showDialog,
    close: hideDialog,
  } = useDialog({
    bindShow,
    onCancel,
    onSuccess: onConfirm,
  });

  useEffect(() => {
    if (show) {
      showDialog();
    }
  }, [show]);

  if (!show) {
    return <></>;
  }

  return (
    <Dialog {...dialogProps}>
      <DialogTitle>
        <h1>{title}</h1>
      </DialogTitle>
      <DialogContent>{children}</DialogContent>
      <DialogActions>
        <Button onClick={() => hideDialog(false)} subtle>
          Cancel
        </Button>
        <Button
          onClick={() => hideDialog(true)}
          alert={theme === ConfirmationDialogTheme.Alert}
        >
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
