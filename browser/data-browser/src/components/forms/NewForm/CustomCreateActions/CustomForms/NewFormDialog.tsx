import { core, forms, dataBrowser, useStore } from '@tomic/react';
import { useState, useCallback, useEffect, useRef, FormEvent, FC } from 'react';
import { useSettings } from '../../../../../helpers/AppSettings';
import { BetaBadge } from '../../../../BetaBadge';
import { Button } from '../../../../Button';
import {
  useDialog,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
} from '../../../../Dialog';
import Field from '../../../Field';
import { InputWrapper, InputStyled } from '../../../InputStyles';
import type { CustomResourceDialogProps } from '../../useNewResourceUI';
import { singularize } from '../../../../../helpers/singularize';
import { useCreateAndNavigate } from '../../../../../hooks/useCreateAndNavigate';
import { useAddToOntology } from '../../../../../hooks/useAddToOntology';
import {
  createRowClass,
  resolveOntologyParent,
} from '../../../../../chunks/TablePage/createTableFromSpec';
import { styled } from 'styled-components';

/**
 * Suggests what a single response's row should be called: the singular of the
 * typed form name ("Feedback surveys" → "Feedback survey"), else "Response".
 */
const suggestRowName = (formName: string): string =>
  singularize(formName) || 'Response';

export const NewFormDialog: FC<CustomResourceDialogProps> = ({
  parent,
  onClose,
  skipNavigation,
  onCreated,
}) => {
  const store = useStore();
  const { drive: driveSubject } = useSettings();
  const [name, setName] = useState('Form');
  // What a single response is called ("Response", "Application") — names the
  // data class. Follows the form name (singularized) until edited manually.
  const [rowName, setRowName] = useState('Response');
  const [rowNameEdited, setRowNameEdited] = useState(false);
  const nameInputRef = useRef<HTMLInputElement>(null);

  const addToOntology = useAddToOntology();
  const createResourceAndNavigate = useCreateAndNavigate();

  const onCancel = useCallback(() => {
    onClose();
  }, [onClose]);

  const onSuccess = useCallback(async () => {
    const ontologyParent = await resolveOntologyParent(store, driveSubject);
    const dataClass = await createRowClass(store, {
      parent: ontologyParent,
      tableName: name,
      rowName,
    });
    await addToOntology(dataClass);

    // `form-target-table` is a required property on the Form class, so it
    // must be present in the Form's genesis commit — the server rejects a
    // genesis commit missing a required property outright. That means the
    // table's subject has to exist *before* the Form does, so the table is
    // created first with a temporary parent (the same outer `parent` the
    // Form gets) and re-parented to the Form once the Form's subject is
    // known, right alongside the starter page.
    const table = await store.newResource({
      parent,
      isA: dataBrowser.classes.table,
      propVals: {
        [core.properties.name]: name,
        [core.properties.classtype]: dataClass.subject,
      },
    });
    await table.save();

    await createResourceAndNavigate(
      forms.classes.form,
      {
        [core.properties.name]: name,
        [forms.properties.formDataClass]: dataClass.subject,
        [forms.properties.formTargetTable]: table.subject,
        [forms.properties.formPages]: [],
      },
      {
        parent,
        skipNavigation,
        onCreated: async formResource => {
          await table.set(core.properties.parent, formResource.subject);
          await table.save();

          const page = await store.newResource({
            parent: formResource.subject,
            isA: forms.classes.formPage,
            propVals: {
              [core.properties.name]: 'Page 1',
              [forms.properties.formFields]: [],
            },
          });
          await page.save();

          await formResource.set(forms.properties.formPages, [page.subject]);
          await formResource.save();

          onCreated?.(formResource);
        },
      },
    );

    onClose();
  }, [
    name,
    rowName,
    onClose,
    parent,
    addToOntology,
    createResourceAndNavigate,
    skipNavigation,
    onCreated,
    store,
    driveSubject,
  ]);

  const [dialogProps, show, hide, isOpen] = useDialog({ onCancel, onSuccess });

  useEffect(() => {
    show();
  }, []);

  useEffect(() => {
    if (isOpen) {
      nameInputRef.current?.focus();
      nameInputRef.current?.select();
    }
  }, [isOpen]);

  const hasName = name.trim() !== '';
  const hasRowName = rowName.trim() !== '';
  const saveDisabled = !hasName || !hasRowName;

  return (
    <Dialog {...dialogProps}>
      {isOpen && (
        <>
          <RelativeDialogTitle>
            <h1>New Form</h1>
            <BetaBadge />
          </RelativeDialogTitle>
          <DialogContent>
            <form
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                hide(true);
              }}
            >
              <Field required label='Name'>
                <InputWrapper>
                  <InputStyled
                    ref={nameInputRef}
                    placeholder='New Form'
                    value={name}
                    onChange={e => {
                      setName(e.target.value);

                      if (!rowNameEdited) {
                        setRowName(suggestRowName(e.target.value));
                      }
                    }}
                  />
                </InputWrapper>
              </Field>
              <Field
                required
                label='Each response is a'
                helper='Names the class of a single submission — e.g. every response of a Job Application form is an Application.'
              >
                <InputWrapper>
                  <InputStyled
                    placeholder='Response'
                    value={rowName}
                    onChange={e => {
                      setRowName(e.target.value);
                      setRowNameEdited(true);
                    }}
                  />
                </InputWrapper>
              </Field>
            </form>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => hide(false)} subtle>
              Cancel
            </Button>
            <Button onClick={() => hide(true)} disabled={saveDisabled}>
              Create
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );
};

const RelativeDialogTitle = styled(DialogTitle)`
  display: flex;
  align-items: flex-start;
  gap: 1ch;
`;
