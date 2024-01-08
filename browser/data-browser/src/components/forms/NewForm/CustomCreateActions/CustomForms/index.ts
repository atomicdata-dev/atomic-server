import { dataBrowser, core } from '@tomic/react';
import { registerNewResourceDialog } from '../../useNewResourceUI';
import { NewBookmarkDialog } from './NewBookmarkDialog';
import { NewOntologyDialog } from './NewOntologyDialog';
import { NewTableDialog } from './NewTableDialog';

export const registerCustomForms = () => {
  registerNewResourceDialog(dataBrowser.classes.bookmark, NewBookmarkDialog);
  registerNewResourceDialog(core.classes.ontology, NewOntologyDialog);
  registerNewResourceDialog(dataBrowser.classes.table, NewTableDialog);
};
