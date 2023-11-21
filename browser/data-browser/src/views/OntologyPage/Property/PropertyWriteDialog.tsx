import { Resource, urls, useCanWrite, useProperty } from '@tomic/react';

import {
  Dialog,
  DialogContent,
  DialogTitle,
  InternalDialogProps,
} from '../../../components/Dialog';
import { styled } from 'styled-components';
import InputSwitcher from '../../../components/forms/InputSwitcher';
import { PropertyFormCommon } from './PropertyFormCommon';

interface PropertyWriteDialogProps {
  resource: Resource;
  close: () => void;
}

export function PropertyWriteDialog({
  resource,
  close,
  ...dialogProps
}: PropertyWriteDialogProps & InternalDialogProps): JSX.Element {
  const [canEdit] = useCanWrite(resource);
  const shortnameProp = useProperty(urls.properties.shortname);

  return (
    <Dialog {...dialogProps}>
      {dialogProps.show && (
        <>
          <DialogTitle>
            <InputSwitcher
              commit
              disabled={!canEdit}
              resource={resource}
              property={shortnameProp}
            />
          </DialogTitle>
          <WiderDialogContent>
            <PropertyFormCommon
              resource={resource}
              canEdit={canEdit}
              onClassCreated={close}
            />
          </WiderDialogContent>
        </>
      )}
    </Dialog>
  );
}

const WiderDialogContent = styled(DialogContent)`
  width: min(40rem, 90vw);
`;
