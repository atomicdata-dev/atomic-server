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
import type { Template } from './template';
import { useEffect, useMemo, useState } from 'react';
import Markdown from '../datatypes/Markdown';
import { dataBrowser, useResource, useResources, useStore } from '@tomic/react';
import toast from 'react-hot-toast';
import { InlineErrMessage } from '../forms/InputStyles';
import { useSettings } from '../../helpers/AppSettings';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../../helpers/navigation';

interface ApplyTemplateDialogProps {
  template?: Template;
  open: boolean;
  bindOpen: (open: boolean) => void;
}

const stableArray = [];

export function ApplyTemplateDialog({
  template,
  bindOpen,
  open = false,
}: ApplyTemplateDialogProps): React.JSX.Element {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [dialogProps, show, close, isOpen] = useDialog({ bindShow: bindOpen });
  const { drive } = useSettings();
  const driveResource = useResource(drive);
  const [error, setError] = useState<string>();

  const subjects = useMemo(
    () =>
      template?.rootResourceLocalIDs.map(localID =>
        new URL(localID, drive + '/').toString(),
      ) ?? stableArray,
    [template, drive],
  );

  const resources = useResources(subjects);

  const formattedJSONAD = template
    ? JSON.stringify(template.resources, null, 2)
    : '';

  const alreadyApplied = Array.from(resources.values()).some(r => !r.error);

  const applyTemplate = async () => {
    if (!template) return;

    for (const resource of resources.keys()) {
      // The resources are in the store but might have errors because they don't exist. We need to remove them so they're not cached when we navigate to them later.
      store.removeResource(resource);
    }

    try {
      await store.importJsonAD(JSON.stringify(template.resources), {
        parent: drive,
      });

      driveResource.push(dataBrowser.properties.subResources, subjects);
      await driveResource.save();

      close();
      toast.success('Template applied!');
      navigate(constructOpenURL(subjects[0]));
    } catch (err) {
      setError(err.message);
    }
  };

  useEffect(() => {
    if (open) {
      show();
    }
  }, [open]);

  return (
    <Dialog {...dialogProps} width='50rem'>
      {isOpen && template && (
        <>
          <DialogTitle>
            <h1>Apply {template.title} template</h1>
          </DialogTitle>
          <DialogContent>
            <Column>
              <Markdown
                text={template.description({ serverUrl: store.getServerUrl() })}
              />
              <Details title='Preview JSON-AD'>
                <CodeBlock content={formattedJSONAD} />
              </Details>
            </Column>
          </DialogContent>
          <DialogActions>
            {error && <InlineErrMessage>{error}</InlineErrMessage>}
            {alreadyApplied && (
              <InlineErrMessage>
                This template has already been applied to this drive
              </InlineErrMessage>
            )}
            <Button
              onClick={applyTemplate}
              disabled={!!error || alreadyApplied}
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
