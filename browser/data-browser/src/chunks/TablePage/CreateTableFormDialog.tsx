import { core, forms, Resource, useStore } from '@tomic/react';
import { useEffect, useId, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import toast from 'react-hot-toast';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  useDialog,
} from '@components/Dialog';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Checkbox, CheckboxLabel } from '@components/forms/Checkbox';
import { useTableFormColumns } from '../FormBuilder/useTableFormColumns';
import {
  compatibleFieldTypes,
  columnLabel,
  createMappedField,
} from '../FormBuilder/tableColumns';
import { constructOpenURL } from '@helpers/navigation';

export function CreateTableFormDialog({
  table,
  dataClassSubject,
  onClose,
}: {
  table: Resource;
  dataClassSubject: string;
  onClose: () => void;
}) {
  const nameId = useId();
  const store = useStore();
  const navigate = useNavigate();
  const { dataClass, columns, requires, loading } =
    useTableFormColumns(dataClassSubject);
  const [name, setName] = useState('New form');
  const [excluded, setExcluded] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [dialogProps, show, hide] = useDialog({
    onCancel: onClose,
    onSuccess: onClose,
  });

  useEffect(() => show(), [show]);

  const create = async () => {
    setBusy(true);

    try {
      const form = await store.newResource({
        parent: table.subject,
        isA: forms.classes.form,
        propVals: {
          [core.properties.name]: name.trim(),
          [forms.properties.formDataClass]: dataClassSubject,
          [forms.properties.formTargetTable]: table.subject,
          [forms.properties.formPages]: [],
        },
      });
      await form.save();
      const page = await store.newResource({
        parent: form.subject,
        isA: forms.classes.formPage,
        propVals: {
          [core.properties.name]: 'Page 1',
          [forms.properties.formFields]: [],
        },
      });
      await page.save();
      // Link immediately so even an interrupted creation leaves a recoverable form.
      await form.set(forms.properties.formPages, [page.subject]);
      await form.save();

      for (const property of columns.filter(
        p => !excluded.includes(p.subject) && compatibleFieldTypes(p).length,
      )) {
        const field = await createMappedField(store, page, dataClass, property);
        await page.set(forms.properties.formFields, [
          ...page.getSubjects(forms.properties.formFields),
          field.subject,
        ]);
        await page.save();
      }

      store.notifyResourceManuallyCreated(form);
      hide();
      await navigate({ to: constructOpenURL(form.subject) });
    } catch (error) {
      toast.error((error as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>Create form from this table</h1>
        </DialogTitle>
        <DialogContent>
          <Column>
            <Field label='Form name' fieldId={nameId} required>
              <InputWrapper>
                <InputStyled
                  id={nameId}
                  autoFocus
                  disabled={busy}
                  value={name}
                  onChange={e => setName(e.target.value)}
                />
              </InputWrapper>
            </Field>
            <p>
              Select the columns to include. Responses will be added to this
              table.
            </p>
            {columns.map(property => {
              const supported = compatibleFieldTypes(property).length > 0;

              return (
                <CheckboxLabel key={property.subject}>
                  <Checkbox
                    disabled={!supported || busy}
                    checked={supported && !excluded.includes(property.subject)}
                    onChange={checked =>
                      setExcluded(previous =>
                        checked
                          ? previous.filter(s => s !== property.subject)
                          : [...previous, property.subject],
                      )
                    }
                  />
                  {columnLabel(property)}
                  {requires.includes(property.subject) ? ' (required)' : ''}
                  {!supported ? ' — not supported in forms' : ''}
                </CheckboxLabel>
              );
            })}
          </Column>
        </DialogContent>
        <DialogActions>
          <Button subtle disabled={busy} onClick={() => hide()}>
            Cancel
          </Button>
          <Button disabled={busy || loading || !name.trim()} onClick={create}>
            Create form
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
