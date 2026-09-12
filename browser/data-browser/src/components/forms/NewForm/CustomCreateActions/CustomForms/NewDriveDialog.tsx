import { useEffect, type FC } from 'react';
import toast from 'react-hot-toast';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../../../Dialog';
import { DriveTemplateSetup } from '../../../../../chunks/Templates/DriveTemplateSetup';
import { useSettings } from '../../../../../helpers/AppSettings';
import { useNavigateWithTransition } from '../../../../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../../../../../helpers/navigation';
import type { CustomResourceDialogProps } from '../../useNewResourceUI';

export const NewDriveDialog: FC<CustomResourceDialogProps> = ({
  onClose,
  onCreated,
  skipNavigation,
}) => {
  const { setDrive } = useSettings();
  const navigate = useNavigateWithTransition();
  const [dialogProps, show] = useDialog({ onCancel: onClose });
  useEffect(() => {
    show();
  }, [show]);

  return (
    <Dialog {...dialogProps} width='65rem'>
      <DialogTitle>
        <h2>New drive</h2>
      </DialogTitle>
      <DialogContent>
        <DriveTemplateSetup
          onPreview={onClose}
          onCreated={resource => {
            setDrive(resource.subject);
            onCreated?.(resource);
            onClose();
            if (!skipNavigation) navigate(constructOpenURL(resource.subject));
            toast.success('Drive created');
          }}
        />
      </DialogContent>
    </Dialog>
  );
};
