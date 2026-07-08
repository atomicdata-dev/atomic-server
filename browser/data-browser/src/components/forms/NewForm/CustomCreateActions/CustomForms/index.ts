import { dataBrowser, core, collections, server, forms } from '@tomic/react';
import { registerNewResourceDialog } from '../../useNewResourceUI';
import { NewBookmarkDialog } from './NewBookmarkDialog';
import { NewOntologyDialog } from './NewOntologyDialog';
import { NewTableDialog } from './NewTableDialog';
import { NewDashboardDialog } from './NewDashboardDialog';
import { NewCollectionDialog } from './NewCollectionDialog';
import { NewDriveDialog } from './NewDriveDialog';
import { NewArticleDialog } from './NewArticleDialog';
import { NewFormDialog } from './NewFormDialog';

export const registerCustomForms = () => {
  registerNewResourceDialog(dataBrowser.classes.bookmark, NewBookmarkDialog);
  registerNewResourceDialog(core.classes.ontology, NewOntologyDialog);
  registerNewResourceDialog(dataBrowser.classes.table, NewTableDialog);
  registerNewResourceDialog(dataBrowser.classes.dashboard, NewDashboardDialog);
  registerNewResourceDialog(
    collections.classes.collection,
    NewCollectionDialog,
  );
  registerNewResourceDialog(server.classes.drive, NewDriveDialog);
  registerNewResourceDialog(dataBrowser.classes.article, NewArticleDialog);
  registerNewResourceDialog(forms.classes.form, NewFormDialog);
};
