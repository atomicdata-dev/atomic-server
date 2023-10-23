import { Core, JSONValue, useResource, useStore, useTitle } from '@tomic/react';
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
import { getNamePartFromProps } from '../../../helpers/getNamePartFromProps';

export interface NewFormDialogProps extends NewFormProps {
  closeDialog: (success?: boolean) => void;
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
  const klass = useResource<Core.Class>(classSubject);
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
    closeDialog(true);
  }, [onSave, closeDialog, resource]);

  // Onmount we generate a new subject based on the classtype and the user input.
  useEffectOnce(() => {
    (async () => {
      const namePart = getNamePartFromProps(initialProps ?? {});

      const uniqueSubject = await store.buildUniqueSubjectFromParts(
        [className, namePart],
        parent,
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
        <Button subtle onClick={() => closeDialog(false)}>
          Cancel
        </Button>
        <Button onClick={save} disabled={saving}>
          Save
        </Button>
      </DialogActions>
    </>
  );
};
