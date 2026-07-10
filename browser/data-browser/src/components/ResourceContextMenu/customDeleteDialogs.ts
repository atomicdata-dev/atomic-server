import { forms } from '@tomic/react';
import { registerDeleteDialog } from './deleteDialogRegistry';
import { DeleteFormDialog } from '../../chunks/FormBuilder/DeleteFormDialog';

export const registerCustomDeleteDialogs = () => {
  registerDeleteDialog(forms.classes.form, DeleteFormDialog);
};
