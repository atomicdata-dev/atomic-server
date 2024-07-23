import { useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../components/Dialog';
import { useResource } from '@tomic/react';
import { ResourceCodeUsage } from './ResourceCodeUsage';
import { styled } from 'styled-components';

interface ResourceCodeUsageDialogProps {
  subject: string;
  show: boolean;
  bindShow: (open: boolean) => void;
}

export function ResourceCodeUsageDialog({
  subject,
  show: open,
  bindShow,
}: ResourceCodeUsageDialogProps): React.JSX.Element {
  const resource = useResource(subject);
  const { dialogProps, show, close: hide, isOpen } = useDialog({ bindShow });

  useEffect(() => {
    if (open) {
      show();
    } else {
      hide();
    }
  }, [open]);

  return (
    <Dialog {...dialogProps} width='85ch'>
      {isOpen && (
        <>
          <DialogTitle>
            <h1>
              Use <Name>{resource.title}</Name> in code
            </h1>
          </DialogTitle>
          <StyledDialogContent>
            <ResourceCodeUsage subject={subject} />
          </StyledDialogContent>
        </>
      )}
    </Dialog>
  );
}

const StyledDialogContent = styled(DialogContent)`
  /* height: min(100vh, 40rem) !important; */
  max-height: 90vh;
  overflow-x: hidden;
`;

const Name = styled.span`
  color: ${p => p.theme.colors.textLight};
`;
