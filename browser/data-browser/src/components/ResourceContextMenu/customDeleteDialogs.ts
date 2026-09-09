import { DeleteTableDialog } from '../../chunks/TablePage/DeleteTableDialog';
import { forms, dataBrowser } from '@tomic/react';
import { registerDeleteDialog } from './deleteDialogRegistry';
import { DeleteFormDialog } from '../../chunks/FormBuilder/DeleteFormDialog';

export const registerCustomDeleteDialogs = () => {
  registerDeleteDialog(forms.classes.form, DeleteFormDialog);
  registerDeleteDialog(dataBrowser.classes.table, DeleteTableDialog);
};
