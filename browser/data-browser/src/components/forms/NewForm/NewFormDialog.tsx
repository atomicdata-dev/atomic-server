import {
  JSONValue,
  properties,
  useResource,
  useStore,
  useTitle,
} from '@tomic/react';
import React, { useState, useCallback } from 'react';
import { useEffectOnce } from '../../../hooks/useEffectOnce';
import { Button } from '../../Button';
import { DialogTitle, DialogContent, DialogActions } from '../../Dialog';
import { ErrorLook } from '../../ErrorLook';
import { useSaveResource } from '../hooks/useSaveResource';
import { InlineErrMessage } from '../InputStyles';
import { ResourceForm, ResourceFormVariant } from '../ResourceForm';
import { NewFormProps } from './NewFormPage';
import { NewFormTitle, NewFormTitleVariant } from './NewFormTitle';
import { SubjectField } from './SubjectField';
import { useNewForm } from './useNewForm';
import { randomString } from '../../../helpers/randomString';

export interface NewFormDialogProps extends NewFormProps {
  closeDialog: () => void;
  initialProps?: Record<string, JSONValue>;
  onSave: (subject: string) => void;
  parent: string;
}

/** Form for instantiating a new Resource from some Class in a Modal / Dialog view */
export const NewFormDialog = ({
  classSubject,
  closeDialog,
  initialProps,
  onSave,
  parent,
}: NewFormDialogProps): JSX.Element => {
  const klass = useResource(classSubject);
  const [className] = useTitle(klass);
  const store = useStore();

  const [subject, setSubject] = useState(store.createSubject());

  const { subjectErr, subjectValue, setSubjectValue, resource } = useNewForm({
    klass,
    setSubject,
    initialSubject: subject,
    parent,
  });

  const onResourceSave = useCallback(() => {
    onSave(resource.getSubject());
    closeDialog();
  }, [onSave, closeDialog, resource]);

  // Onmount we generate a new subject based on the classtype and the user input.
  useEffectOnce(() => {
    (async () => {
      const namePart = normalizeName(
        (initialProps?.[properties.shortname] as string) ??
          (initialProps?.[properties.name] as string) ??
          randomString(8),
      );

      const uniqueSubject = await store.buildUniqueSubjectFromParts(
        className,
        namePart,
      );

      await setSubjectValue(uniqueSubject);

      for (const [prop, value] of Object.entries(initialProps ?? {})) {
        await resource.set(prop, value, store);
      }
    })();
  });

  const [save, saving, error] = useSaveResource(resource, onResourceSave);

  if (!parent) {
    return <ErrorLook>No parent set</ErrorLook>;
  }

  return (
    <>
      <DialogTitle>
        <NewFormTitle
          classSubject={classSubject}
          variant={NewFormTitleVariant.Dialog}
        />
      </DialogTitle>
      <DialogContent>
        <SubjectField
          error={subjectErr}
          value={subjectValue}
          onChange={setSubjectValue}
        />
        {/* Key is required for re-rendering when subject changes */}
        <ResourceForm
          resource={resource}
          classSubject={classSubject}
          key={`${classSubject}+${subjectValue}`}
          variant={ResourceFormVariant.Dialog}
          onSave={onResourceSave}
        />
      </DialogContent>
      <DialogActions>
        {error && <InlineErrMessage>{error.message}</InlineErrMessage>}
        <Button subtle onClick={closeDialog}>
          Cancel
        </Button>
        <Button onClick={save} disabled={saving}>
          Save
        </Button>
      </DialogActions>
    </>
  );
};

const normalizeName = (name: string) => name.replaceAll('/t', '-');
