import { useEffect, useState, type JSX } from 'react';
import { useStore } from '@tomic/react';
import {
  FormRenderer,
  FormShell,
  type FormDefinition,
} from '@tomic/form-renderer';
import '@tomic/form-renderer/style.css';
import { Dialog, useDialog } from '@components/Dialog';
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
  const [dialogProps, show, _close, isOpen] = useDialog();

  return (
    <>
      <Button subtle onClick={show}>
        Preview
      </Button>
      <Dialog {...dialogProps} width='40rem'>
        {isOpen && (
          <>
            <Dialog.Title>
              <h1>Preview</h1>
            </Dialog.Title>
            <Dialog.Content>
              <PreviewForm formSubject={formSubject} />
            </Dialog.Content>
          </>
        )}
      </Dialog>
    </>
  );
}

/** Mounted per opening, so each opening starts from "Loading preview…" and
 * builds the definition from the form as it is now. Kept in the button instead,
 * the last definition would outlive the dialog and be what the next opening
 * rendered first: the form as it was before the edits made in between, until
 * the rebuild landed. */
function PreviewForm({ formSubject }: FormPreviewButtonProps): JSX.Element {
  const store = useStore();
  const [definition, setDefinition] = useState<FormDefinition>();

  useEffect(() => {
    let cancelled = false;

    buildFormDefinitionClientSide(store, formSubject).then(def => {
      if (!cancelled) setDefinition(def);
    });

    return () => {
      cancelled = true;
    };
  }, [store, formSubject]);

  if (!definition) return <p>Loading preview…</p>;

  return (
    <FormShell definition={definition}>
      <FormRenderer
        definition={definition}
        preview
        onSubmit={async () => ({ ok: true })}
      />
    </FormShell>
  );
}
