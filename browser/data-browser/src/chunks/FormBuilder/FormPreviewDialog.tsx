import { useEffect, useState, type JSX } from 'react';
import { useStore } from '@tomic/react';
import {
  FormRenderer,
  FormShell,
  type FormDefinition,
} from '@tomic/form-renderer';
import '@tomic/form-renderer/style.css';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  useDialog,
} from '@components/Dialog';
import { Button } from '@components/Button';
import { buildFormDefinitionClientSide } from './buildFormDefinition';

interface FormPreviewButtonProps {
  formSubject: string;
}

/** Renders the form exactly as a visitor would see it at `/form/:id`, using
 * the same `@tomic/form-renderer` component — built from a client-side
 * mirror of the server's definition JSON (`buildFormDefinitionClientSide`).
 * `preview` disables the honeypot and turns Submit into a no-op so no real
 * submission row is ever written from here. */
export function FormPreviewButton({
  formSubject,
}: FormPreviewButtonProps): JSX.Element {
  const store = useStore();
  const [dialogProps, show, _close, isOpen] = useDialog();
  const [definition, setDefinition] = useState<FormDefinition>();

  useEffect(() => {
    if (!isOpen) return;

    let cancelled = false;

    buildFormDefinitionClientSide(store, formSubject).then(def => {
      if (!cancelled) setDefinition(def);
    });

    return () => {
      cancelled = true;
    };
  }, [isOpen, store, formSubject]);

  return (
    <>
      <Button subtle onClick={show}>
        Preview
      </Button>
      <Dialog {...dialogProps} width="40rem">
        {isOpen && (
          <>
            <DialogTitle>
              <h1>Preview</h1>
            </DialogTitle>
            <DialogContent>
              {definition ? (
                <FormShell definition={definition}>
                  <FormRenderer
                    definition={definition}
                    preview
                    onSubmit={async () => ({ ok: true })}
                  />
                </FormShell>
              ) : (
                <p>Loading preview…</p>
              )}
            </DialogContent>
          </>
        )}
      </Dialog>
    </>
  );
}
