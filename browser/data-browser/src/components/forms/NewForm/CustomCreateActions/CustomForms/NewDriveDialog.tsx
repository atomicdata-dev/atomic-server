import { getManagedPortalUrl } from '../../../../../helpers/managed/cloudSync';
import { useStore } from '@tomic/react';
import { useState, useCallback, FormEvent, FC, useEffect, useId } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { constructOpenURL } from '../../../../../helpers/navigation';
import { useNavigateWithTransition } from '../../../../../hooks/useNavigateWithTransition';
import { Button } from '../../../../Button';
import {
  useDialog,
  Dialog,
  DialogContent,
  DialogActions,
  DialogTitle,
} from '../../../../Dialog';
import Field from '../../../Field';
import { InputWrapper, InputStyled } from '../../../InputStyles';
import { CustomResourceDialogProps } from '../../useNewResourceUI';
import { useSettings } from '../../../../../helpers/AppSettings';

export const NewDriveDialog: FC<CustomResourceDialogProps> = ({
  onClose,
  onCreated,
  skipNavigation,
}) => {
  const store = useStore();
  const nameFieldId = useId();
  const { setDrive } = useSettings();
  const [name, setName] = useState('');

  const navigate = useNavigateWithTransition();

  const onSuccess = useCallback(async () => {
    if (!name.trim()) return;

    try {
      // `createDrive` owns all drive invariants (permissions, saved-drives
      // list, default ontology); this dialog only adds UI concerns.
      const resource = await store.createDrive(name, {
        // An ADDITIONAL drive: linked into the switcher list, but it does not
        // replace the agent's personal/home drive.
        personal: false,
        localOnly: !!getManagedPortalUrl(),
      });

      store.notifyResourceManuallyCreated(resource);

      // Change current drive to the new drive — before navigation.
      setDrive(resource.subject);

      if (!skipNavigation) {
        navigate(constructOpenURL(resource.subject));
      }

      toast.success('Drive created');
      onCreated?.(resource);
    } catch (e) {
      store.notifyError(e);
      toast.error('Failed to create drive');
    }

    onClose();
  }, [name, navigate, onClose, setDrive, store, onCreated, skipNavigation]);

  const [dialogProps, show, hide] = useDialog({ onSuccess, onCancel: onClose });

  useEffect(() => {
    show();
  }, []);

  return (
    <Dialog {...dialogProps}>
      <DialogTitle>
        <H1>New Drive</H1>
      </DialogTitle>
      <DialogContent>
        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            hide(true);
          }}
        >
          <Field required label='Name' fieldId={nameFieldId}>
            <InputWrapper>
              <InputStyled
                id={nameFieldId}
                placeholder='My Drive'
                value={name}
                autoFocus={true}
                onChange={e => setName(e.target.value)}
              />
            </InputWrapper>
          </Field>
        </form>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => hide(false)} subtle>
          Cancel
        </Button>
        <Button onClick={() => hide(true)} disabled={!name.trim()}>
          Create
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const H1 = styled.h1`
  margin: 0;
`;
