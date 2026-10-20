import { useEffect, useState, type JSX } from 'react';
import toast from 'react-hot-toast';
import {
  core,
  unknownSubject,
  useCanWrite,
  useResource,
  useStore,
} from '@tomic/react';
import { Button } from './Button';
import { Column } from './Row';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from './Dialog';
import { ResourceSelector } from './forms/ResourceSelector';
import { moveBlockedReason } from '../helpers/moveResource';

interface MoveResourceDialogProps {
  subject: string;
  show: boolean;
  onShowChange: (show: boolean) => void;
}

/** Re-parents a resource within its drive. Opened from the More menu. */
export function MoveResourceDialog({
  subject,
  show,
  onShowChange,
}: MoveResourceDialogProps): JSX.Element {
  const store = useStore();
  const [target, setTarget] = useState<string>();
  const targetResource = useResource(target ?? unknownSubject);
  const canWriteTarget = useCanWrite(targetResource);
  const [dialogProps, showDialog, closeDialog] = useDialog({
    bindShow: onShowChange,
  });

  useEffect(() => {
    if (show) {
      showDialog();
    }
  }, [show, showDialog]);

  const blocked = target
    ? moveBlockedReason(store, subject, target)
    : undefined;
  const noRights = target && !blocked && !canWriteTarget;
  const current = store.getResourceLoading(subject).get(core.properties.parent);
  const unchanged = target === current;
  const ready = !!target && !blocked && !noRights && !unchanged;

  const move = async () => {
    if (!target) return;

    try {
      const resource = await store.getResource(subject);
      await resource.set(core.properties.parent, target);
      await resource.save();
      closeDialog(true);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <Dialog {...dialogProps}>
      {show && (
        <>
          <DialogTitle>
            <h1>Move</h1>
          </DialogTitle>
          <DialogContent>
            <Column>
              <ResourceSelector
                setSubject={setTarget}
                value={target}
                hideCreateOption
                autoFocus
              />
              {blocked && <p>{blocked}</p>}
              {noRights && <p>You don't have write access to that location.</p>}
              <p>
                Access follows the new parent: who can see or edit this may
                change.
              </p>
            </Column>
          </DialogContent>
          <DialogActions>
            <Button subtle onClick={() => closeDialog(false)}>
              Cancel
            </Button>
            <Button disabled={!ready} onClick={move}>
              Move
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );
}
