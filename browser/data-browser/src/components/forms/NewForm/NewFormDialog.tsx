import { Core, JSONValue, useResource } from '@tomic/react';
import { useState, useCallback } from 'react';
import { useEffectOnce } from '../../../hooks/useEffectOnce';
import { Button } from '../../Button';
import { DialogTitle, DialogContent, DialogActions } from '../../Dialog';
import { ErrorBlock, ErrorLook } from '../../ErrorLook';
import { useSaveResource } from '../hooks/useSaveResource';
import { InlineErrMessage } from '../InputStyles';
import { ResourceForm, ResourceFormVariant } from '../ResourceForm';
import { NewFormProps } from './NewFormPage';
import { NewFormTitle, NewFormTitleVariant } from './NewFormTitle';
import { SubjectField } from './SubjectField';
import { useNewForm } from './useNewForm';

export interface NewFormDialogProps extends NewFormProps {
  initialProps?: Record<string, JSONValue>;
  parent: string;
  onSaveClick: (subject: string) => void;
  onCancel: () => void;
}

/** Form for instantiating a new Resource from some Class in a Modal / Dialog view */
export const NewFormDialog = ({
  classSubject,
  onCancel,
  initialProps,
  onSaveClick,
  parent,
}: NewFormDialogProps): JSX.Element => {
  const klass = useResource<Core.Class>(classSubject);
  const [subject, setSubject] = useState<string>();
  const [isFormValid, setIsFormValid] = useState(false);
  const { subjectErr, subjectValue, setSubjectValue, resource } = useNewForm({
    klass,
    setSubject,
    initialSubject: subject,
    parent,
  });

  const handleValidationChange = useCallback((valid: boolean) => {
    setIsFormValid(valid);
  }, []);

  const [initialValuesSet, setInitialValuesSet] = useState(false);

  const onResourceSave = useCallback(() => {
    onSaveClick(resource.subject);
  }, [onSaveClick, resource]);

  // Onmount we generate a new subject based on the classtype and the user input.
  useEffectOnce(() => {
    (async () => {
      for (const [prop, value] of Object.entries(initialProps ?? {})) {
        await resource.set(prop, value);
      }

      setInitialValuesSet(true);
    })();
  });

  const [save, saving, error] = useSaveResource(resource, onResourceSave);

  if (!parent) {
    return <ErrorLook>No parent set</ErrorLook>;
  }

  if (resource.error) {
    return <ErrorBlock error={resource.error}></ErrorBlock>;
  }

  if (!initialValuesSet) {
    return <>loading</>;
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
          onValidationChange={handleValidationChange}
        />
      </DialogContent>
      <DialogActions>
        {error && <InlineErrMessage>{error.message}</InlineErrMessage>}
        <Button subtle onClick={onCancel}>
          Cancel
        </Button>
        <Button onClick={save} disabled={saving || !isFormValid}>
          Save
        </Button>
      </DialogActions>
    </>
  );
};
