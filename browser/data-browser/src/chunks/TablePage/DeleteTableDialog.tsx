import { core, forms, useCollection, useStore } from '@tomic/react';
import toast from 'react-hot-toast';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '@components/ConfirmationDialog';
import type { DeleteDialogProps } from '@components/ResourceContextMenu/deleteDialogRegistry';
import { deleteTableForms } from '../FormBuilder/deleteForm';

export function DeleteTableDialog({
  resource,
  show,
  bindShow,
  onDeleted,
}: DeleteDialogProps) {
  const store = useStore();
  const { collection, ready } = useCollection({
    property: core.properties.parent,
    value: resource.subject,
    filters: [{ property: core.properties.isA, value: forms.classes.form }],
  });

  return (
    <ConfirmationDialog
      title='Delete table'
      show={show}
      bindShow={bindShow}
      theme={ConfirmationDialogTheme.Alert}
      confirmLabel='Delete'
      onConfirm={async () => {
        try {
          await deleteTableForms(store, resource);
          const parent = resource.get(core.properties.parent) as
            | string
            | undefined;
          await resource.destroy();
          onDeleted(parent);
        } catch (error) {
          toast.error((error as Error).message);
        }
      }}
    >
      <p>Are you sure you want to delete this table?</p>
      <p>
        {ready
          ? `${collection.totalMembers} attached forms will also be deleted, including their pages and questions.`
          : 'Attached forms will also be deleted, including their pages and questions.'}
      </p>
    </ConfirmationDialog>
  );
}
