import { core, forms, useStore, useString } from '@tomic/react';
import { CollectionBuilder } from '@tomic/lib';
import { useState, type JSX } from 'react';
import toast from 'react-hot-toast';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '@components/ConfirmationDialog';
import { Checkbox, CheckboxLabel } from '@components/forms/Checkbox';
import type { DeleteDialogProps } from '@components/ResourceContextMenu/deleteDialogRegistry';

/**
 * `Resource.destroy()` never cascades (`browser/lib/src/resource.ts`), so
 * deleting a Form through the generic delete action already keeps the
 * target table + submissions intact for free. This dialog adds the explicit
 * opt-in to also remove them — the table's row children (filtered by
 * `parent` + `isA` the table's row class, same query shape as
 * `useSubmissionCount`) are destroyed first, then the table, then the form.
 * The generated data Class/Properties are deliberately left alone.
 *
 * Registered in `customDeleteDialogs.ts` as the delete dialog for the Form
 * class, so it replaces the generic delete confirmation everywhere a Form's
 * context menu appears (navbar, sidebar, cards), not just in the builder.
 */
export function DeleteFormDialog({
  resource: formResource,
  show,
  bindShow,
  onDeleted,
}: DeleteDialogProps): JSX.Element {
  const store = useStore();
  const [cascade, setCascade] = useState(false);
  const [tableSubject] = useString(
    formResource,
    forms.properties.formTargetTable,
  );

  const onConfirm = async () => {
    try {
      if (cascade && tableSubject) {
        const table = await store.getResource(tableSubject);
        const classSubject = table.get(core.properties.classtype) as
          | string
          | undefined;

        const collection = await new CollectionBuilder(store)
          .setProperty(core.properties.parent)
          .setValue(tableSubject)
          .setFilters(
            classSubject
              ? [{ property: core.properties.isA, value: classSubject }]
              : [],
          )
          .buildAndFetch();

        for await (const rowSubject of collection) {
          const row = await store.getResource(rowSubject);
          await row.destroy();
        }

        await table.destroy();
      }

      const parent = formResource.get(core.properties.parent) as
        | string
        | undefined;
      await formResource.destroy();
      onDeleted(parent);
    } catch (error) {
      toast.error((error as Error).message);
    }
  };

  return (
    <ConfirmationDialog
      title='Delete form'
      show={show}
      bindShow={bindShow}
      theme={ConfirmationDialogTheme.Alert}
      confirmLabel='Delete'
      onConfirm={onConfirm}
    >
      <p>Are you sure you want to delete this form?</p>
      <CheckboxLabel>
        <Checkbox checked={cascade} onChange={setCascade} />
        Also delete the results table and its responses
      </CheckboxLabel>
    </ConfirmationDialog>
  );
}
