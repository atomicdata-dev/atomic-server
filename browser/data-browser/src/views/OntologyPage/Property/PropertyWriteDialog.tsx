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
import { isContentAddressed } from '../../../helpers/propertyIdentity';

import type { JSX } from 'react';

interface PropertyWriteDialogProps {
  resource: Resource;
  close: () => void;
  isOpen: boolean;
  /** The class whose line opened the dialog: where a link's class is stored. */
  classResource?: Resource;
}

export function PropertyWriteDialog({
  resource,
  close,
  isOpen,
  classResource,
  ...dialogProps
}: PropertyWriteDialogProps & InternalDialogProps): JSX.Element {
  const canEdit = useCanWrite(resource);
  const shortnameProp = useProperty(urls.properties.shortname);

  return (
    <Dialog {...dialogProps} width='min(40rem, 90vw)'>
      {isOpen && (
        <>
          <DialogTitle>
            <InputSwitcher
              commit
              // The shortname is part of a content-addressed property's ID.
              disabled={!canEdit || isContentAddressed(resource.subject)}
              resource={resource}
              property={shortnameProp}
            />
          </DialogTitle>
          <DialogContent>
            {/* Spacer fixes an issue where the top border of the description field gets cut of by the container */}
            <Spacer />
            <PropertyFormCommon
              resource={resource}
              canEdit={canEdit}
              classResource={classResource}
              onClassCreated={close}
            />
          </DialogContent>
        </>
      )}
    </Dialog>
  );
}

const Spacer = styled.div`
  height: 2px;
`;
