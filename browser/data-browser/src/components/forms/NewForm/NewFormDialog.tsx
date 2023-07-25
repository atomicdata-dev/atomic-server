import { properties, useResource, useStore, useTitle } from '@tomic/react';
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

export interface NewFormDialogProps extends NewFormProps {
  closeDialog: () => void;
  initialTitle: string;
  onSave: (subject: string) => void;
  parent: string;
}

/** Form for instantiating a new Resource from some Class in a Modal / Dialog view */
export const NewFormDialog = ({
  classSubject,
  closeDialog,
  initialTitle,
  onSave,
  parent,
}: NewFormDialogProps): JSX.Element => {
  const klass = useResource(classSubject);
  const [className] = useTitle(klass);
  const store = useStore();
  // Wrap in useState to avoid changing the value when the prop changes.
  const [initialShortname] = useState(initialTitle);

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
    store.buildUniqueSubjectFromParts(className, initialShortname).then(val => {
      setSubjectValue(val);
    });

    // Set the shortname to the initial user input of a dropdown.
    // In the future we might need to change this when we want to have forms other than `property` and`class` in dialogs.
    resource.set(properties.shortname, initialShortname, store);
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
