import { dataBrowser, core, collections, server } from '@tomic/react';
import { registerNewResourceDialog } from '../../useNewResourceUI';
import { NewBookmarkDialog } from './NewBookmarkDialog';
import { NewOntologyDialog } from './NewOntologyDialog';
import { NewTableDialog } from './NewTableDialog';
import { NewCollectionDialog } from './NewCollectionDialog';
import { NewDriveDialog } from './NewDriveDialog';

export const registerCustomForms = () => {
  registerNewResourceDialog(dataBrowser.classes.bookmark, NewBookmarkDialog);
  registerNewResourceDialog(core.classes.ontology, NewOntologyDialog);
  registerNewResourceDialog(dataBrowser.classes.table, NewTableDialog);
  registerNewResourceDialog(
    collections.classes.collection,
    NewCollectionDialog,
  );
  registerNewResourceDialog(server.classes.drive, NewDriveDialog);
};
