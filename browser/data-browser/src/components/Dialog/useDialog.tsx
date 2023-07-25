import { useCallback, useMemo, useState } from 'react';
import { InternalDialogProps } from './index';

export type UseDialogReturnType = [
  /** Props meant to pass to a {@link Dialog} component */
  dialogProps: InternalDialogProps,
  /** Function to show the dialog */
  show: () => void,
  /** Function to close the dialog */
  close: () => void,
  /** Boolean indicating wether the dialog is currently open */
  isOpen: boolean,
];

/** Sets up state, and functions to use with a {@link Dialog} */
export const useDialog = (): UseDialogReturnType => {
  const [showDialog, setShowDialog] = useState(false);
  const [visible, setVisible] = useState(false);

  const show = useCallback(() => {
    setShowDialog(true);
    setVisible(true);
  }, []);

  const close = useCallback(() => {
    setShowDialog(false);
  }, []);

  const handleClosed = useCallback(() => {
    setVisible(false);
  }, []);

  /** Props that should be passed to a {@link Dialog} component. */
  const dialogProps = useMemo<InternalDialogProps>(
    () => ({
      show: showDialog,
      onClose: close,
      onClosed: handleClosed,
    }),
    [showDialog, close, handleClosed],
  );

  return [dialogProps, show, close, visible];
};
