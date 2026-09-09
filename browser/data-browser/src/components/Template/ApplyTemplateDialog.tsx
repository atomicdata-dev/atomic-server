import { FaCheck } from 'react-icons/fa6';
import { Button } from '../Button';
import { CodeBlock } from '../CodeBlock';
import { Details } from '../Details';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  useDialog,
} from '../Dialog';
import { Column } from '../Row';
import { useCallback, useEffect, useState } from 'react';
import Markdown from '../datatypes/Markdown';
import { useStore } from '@tomic/react';
import toast from 'react-hot-toast';
import { InlineErrMessage } from '../forms/InputStyles';
import { useSettings } from '../../helpers/AppSettings';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../../helpers/navigation';
import type { Template } from './template';

interface ApplyTemplateDialogProps {
  template?: Template;
  parent?: string;
  open: boolean;
  bindOpen: (open: boolean) => void;
}

export function ApplyTemplateDialog({
  template,
  parent,
  bindOpen,
  open = false,
}: ApplyTemplateDialogProps): React.JSX.Element {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [dialogProps, show, close, isOpen] = useDialog({ bindShow: bindOpen });
  const { drive } = useSettings();
  const destination = parent ?? drive;
  const [error, setError] = useState<string>();
  const [applying, setApplying] = useState(false);
  const [existingRootSubject, setExistingRootSubject] = useState<string>();

  const formattedJSONAD = template
    ? JSON.stringify(template.resources, null, 2)
    : '';

  const findRootSubject = useCallback(async () => {
    const rootLocalId = template?.rootResourceLocalIDs[0];

    if (!rootLocalId) return undefined;

    const resource = await store.findByLocalId(drive, destination, rootLocalId);

    return resource?.subject;
  }, [drive, destination, store, template]);

  const alreadyApplied = existingRootSubject !== undefined;

  const applyTemplate = async () => {
    if (!template) return;

    setApplying(true);

    try {
      // The imported resources set `parent`; children are resolved via the
      // `parent=` query, so no explicit child list needs maintaining.
      await store.importJsonAD(JSON.stringify(template.resources), {
        parent: destination,
      });
      const rootSubject = await findRootSubject();

      if (!rootSubject) {
        throw new Error('The imported template root could not be found.');
      }

      close();
      toast.success('Template applied!');
      navigate(constructOpenURL(rootSubject));
    } catch (err) {
      setApplying(false);
      setError(err.message);
    }
  };

  useEffect(() => {
    if (open) {
      show();
      setExistingRootSubject(undefined);
      setError(undefined);
      setApplying(false);
      void findRootSubject()
        .then(setExistingRootSubject)
        .catch(e => setError(String(e)));
    }
  }, [findRootSubject, open, show]);

  return (
    <Dialog {...dialogProps} width='50rem'>
      {isOpen && template && (
        <>
          <DialogTitle>
            <h1>Apply {template.title} template</h1>
          </DialogTitle>
          <DialogContent>
            <Column>
              <Markdown text={template.description} />
              <Details title='Preview JSON-AD'>
                <CodeBlock content={formattedJSONAD} />
              </Details>
            </Column>
          </DialogContent>
          <DialogActions>
            {error && <InlineErrMessage>{error}</InlineErrMessage>}
            {alreadyApplied && (
              <InlineErrMessage>
                This template has already been applied here
              </InlineErrMessage>
            )}
            <Button
              onClick={applyTemplate}
              disabled={!!error || alreadyApplied || applying}
              loading={applying ? 'Applying template…' : undefined}
            >
              <FaCheck />
              Apply template
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );
}
