import { useEffect, useState } from 'react';
import { useStore, type Store } from '@tomic/react';
import { FaDownload } from 'react-icons/fa6';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../components/Dialog';
import { Checkbox, CheckboxLabel } from '../../components/forms/Checkbox';
import { ButtonLink } from '../../components/ButtonLink';

interface TableExportDialogProps {
  subject: string;
  show: boolean;
  bindShow: React.Dispatch<boolean>;
}

const buildLink = (subject: string, refAsSubject: boolean, store: Store) => {
  const url = new URL(`${store.getServerUrl()}/export`);

  url.searchParams.set('format', 'csv');
  url.searchParams.set('subject', subject);
  url.searchParams.set('display_refs_as_name', refAsSubject ? 'false' : 'true');

  return url.toString();
};

export function TableExportDialog({
  subject,
  show,
  bindShow,
}: TableExportDialogProps): React.JSX.Element {
  const store = useStore();
  const { dialogProps, show: showDialog } = useDialog({ bindShow });
  const [refAsSubject, setRefAsSubject] = useState(false);

  const url = buildLink(subject, refAsSubject, store);

  useEffect(() => {
    if (show) {
      showDialog();
    }
  }, [show, showDialog]);

  return (
    <>
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>Export table as CSV</h1>
        </DialogTitle>
        <DialogContent>
          <CheckboxLabel>
            <Checkbox checked={refAsSubject} onChange={setRefAsSubject} />{' '}
            Reference resources by subject instead of name.
          </CheckboxLabel>
        </DialogContent>
        <DialogActions>
          <ButtonLink download href={url}>
            <FaDownload />
            Download
          </ButtonLink>
        </DialogActions>
      </Dialog>
    </>
  );
}
