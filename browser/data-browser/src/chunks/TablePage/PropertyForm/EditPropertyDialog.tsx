import {
  Resource,
  core,
  dataBrowser,
  getEffectiveConstraint,
  setClassConstraint,
  useStore,
} from '@tomic/react';
import toast from 'react-hot-toast';
import { useCallback, useContext, useEffect, useState, type JSX } from 'react';
import { PropertyForm } from './PropertyForm';
import { FormValidationContextProvider } from '@components/forms/formValidation/FormValidationContextProvider';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '@components/Dialog';
import { Button } from '@components/Button';
import { getCategoryFromResource } from './categories';
import { TablePageContext } from '../tablePageContext';
import {
  CONSTRAINT_FIELDS,
  applyDraftConstraint,
  seedDraftFromConstraint,
} from './columnConstraints';
import {
  applyDraftFields,
  createPropertyDraft,
  isContentAddressed,
  recreatePropertyWithDatatype,
} from '@helpers/propertyIdentity';

// What an immutable Property leaves to the table class's constraints.
const CONSTRAINT_OMIT = {
  fields: CONSTRAINT_FIELDS,
  classes: [dataBrowser.classes.rangeProperty],
};

interface EditPropertyDialogProps {
  resource: Resource;
  showDialog: boolean;
  bindShow: React.Dispatch<boolean>;
}

export function EditPropertyDialog({
  resource,
  showDialog,
  bindShow,
}: EditPropertyDialogProps): JSX.Element {
  const store = useStore();
  const { tableClassSubject } = useContext(TablePageContext);
  const [valid, setValid] = useState(true);
  // Edits go to a draft copy so a datatype change (which needs a new property)
  // never touches the saved one. A select's tags are children of the property
  // itself and its datatype is fixed, so it edits the property directly.
  const [draft, setDraft] = useState<Resource | null>(null);

  const category = getCategoryFromResource(resource);
  const usesDraft = category !== 'select';

  const onSuccess = useCallback(async () => {
    try {
      if (!draft) {
        await resource.save();

        return;
      }

      const datatypeChanged =
        draft.get(core.properties.datatype) !==
        resource.get(core.properties.datatype);
      const contentAddressed = isContentAddressed(resource.subject);
      const tableClass = await store.getResource(tableClassSubject);
      const hasClass = tableClass.hasClasses(core.classes.class);

      if (datatypeChanged && contentAddressed) {
        // The datatype is part of the property's ID: make a new property and
        // swap it in; a lens carries the stored values over. Legacy
        // properties still change in place below.
        const created = await recreatePropertyWithDatatype(
          store,
          resource,
          draft,
          hasClass ? [tableClass] : [],
          CONSTRAINT_OMIT,
        );

        if (hasClass) {
          // The limits and linked class follow the column to its new property.
          await setClassConstraint(tableClass, resource.subject, undefined);
          await applyDraftConstraint(tableClass, created.subject, draft);
          await tableClass.save();
        }

        return;
      }

      // Limits and the linked class are the class's, not the Property's. A
      // legacy property keeps its own copy in step for readers that predate
      // the class map.
      await applyDraftFields(
        resource,
        draft,
        contentAddressed ? CONSTRAINT_OMIT : undefined,
      );
      await resource.save();

      if (hasClass) {
        await applyDraftConstraint(tableClass, resource.subject, draft);
        await tableClass.save();
      }
    } catch (err) {
      console.error('Failed to save property', err);
      toast.error(`Failed to save column: ${(err as Error).message}`);
    }
  }, [store, resource, draft, tableClassSubject]);

  const [dialogProps, show, hide, visible] = useDialog({ bindShow, onSuccess });

  useEffect(() => {
    if (!showDialog) {
      hide();
      setDraft(null);

      return;
    }

    let cancelled = false;

    (async () => {
      if (usesDraft) {
        const created = await createPropertyDraft(
          store,
          resource.get(core.properties.parent) as string,
          { source: resource },
        );

        if (cancelled) {
          return;
        }

        // Open on what applies to the column in this table.
        seedDraftFromConstraint(
          created,
          getEffectiveConstraint(store, [tableClassSubject], resource.subject),
        );
        setDraft(created);
      }

      show();
    })().catch(console.error);

    return () => {
      cancelled = true;
    };
  }, [showDialog]);

  const handleSaveClick = useCallback(() => {
    hide(true);
  }, [hide]);

  return (
    <FormValidationContextProvider onValidationChange={setValid}>
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>Edit Column</h1>
        </DialogTitle>
        <DialogContent>
          {visible && (draft || !usesDraft) && (
            <PropertyForm
              existingProperty
              resource={draft ?? resource}
              category={category}
              onSubmit={handleSaveClick}
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleSaveClick} disabled={!valid}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </FormValidationContextProvider>
  );
}
