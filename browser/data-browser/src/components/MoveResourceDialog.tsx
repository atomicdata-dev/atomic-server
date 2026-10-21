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
import { WarningBlock } from './WarningBlock';
import { Checkbox } from './forms/Checkbox';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { moveToTrash } from '../helpers/trash';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from './Dialog';
import { ResourceSelector } from './forms/ResourceSelector';
import {
  copyResourceTree,
  moveBlockedReason,
  replaceWithRedirect,
  trashDescendants,
} from '../helpers/moveResource';

interface MoveResourceDialogProps {
  subject: string;
  show: boolean;
  onShowChange: (show: boolean) => void;
}

/**
 * Moves a resource: re-parents it within its drive, or copies it to another
 * drive (new id) and leaves a Redirect or a Trash entry behind. Opened from
 * the More menu.
 */
export function MoveResourceDialog({
  subject,
  show,
  onShowChange,
}: MoveResourceDialogProps): JSX.Element {
  const store = useStore();
  const [target, setTarget] = useState<string>();
  const targetResource = useResource(target ?? unknownSubject);
  const canWriteTarget = useCanWrite(targetResource);
  const [redirect, setRedirect] = useState(true);
  const navigate = useNavigateWithTransition();
  const sourceResource = useResource(subject);
  const canWriteSource = useCanWrite(sourceResource);
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
  const otherDrive =
    !!target &&
    !blocked &&
    store.driveOfSubject(subject) !== store.driveOfSubject(target);
  const noSourceRights = otherDrive && !canWriteSource;
  const current = store.getResourceLoading(subject).get(core.properties.parent);
  const unchanged = target === current;
  const ready =
    !!target && !blocked && !noRights && !noSourceRights && !unchanged;

  const move = async () => {
    if (!target) return;

    try {
      if (otherDrive) {
        const copy = await copyResourceTree(store, subject, target);
        const original = await store.getResource(subject);

        if (redirect) {
          await replaceWithRedirect(original, copy);
          await trashDescendants(store, subject);
        } else {
          await moveToTrash(store, subject, store.driveOfSubject(subject));
        }

        closeDialog(true);
        navigate(constructOpenURL(copy));

        return;
      }

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
              {noSourceRights && (
                <p>You don't have write access to the original.</p>
              )}
              {otherDrive ? (
                <WarningBlock>
                  <WarningBlock.Title>
                    Moving to another drive
                  </WarningBlock.Title>
                  <p>
                    This makes a copy with a new identifier, so its link
                    changes. Links and references elsewhere keep pointing at the
                    old identifier; they only keep working through the redirect.
                    Access follows the new parent.
                  </p>
                  <Checkbox.Label>
                    <Checkbox checked={redirect} onChange={setRedirect} />
                    Leave a redirect at the old location
                  </Checkbox.Label>
                  {!redirect && (
                    <p>The original is moved to the Trash of its drive.</p>
                  )}
                </WarningBlock>
              ) : (
                <p>
                  Access follows the new parent: who can see or edit this may
                  change.
                </p>
              )}
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
