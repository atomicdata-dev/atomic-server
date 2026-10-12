import {
  Core,
  Datatype,
  JSONValue,
  Resource,
  core,
  dataBrowser,
  server,
  useStore,
} from '@tomic/react';
import { useCallback, useEffect, useState, type JSX } from 'react';
import { stringToSlug } from '@helpers/stringToSlug';
import { PropertyFormCategory } from './categories';
import {
  copyablePropertyFields,
  createPropertyDraft,
} from '@helpers/propertyIdentity';
import {
  createPropertyOnClass,
  createSelectPropertyOnClass,
  type TagSeed,
} from '../Kanban/createSelectProperty';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '@components/Dialog';
import { Button } from '@components/Button';
import { FormValidationContextProvider } from '@components/forms/formValidation/FormValidationContextProvider';
import { PropertyForm } from './PropertyForm';
import {
  CONSTRAINT_FIELDS,
  constraintPatchFromDraft,
} from './columnConstraints';

interface NewPropertyDialogProps {
  showDialog: boolean;
  tableClassResource: Resource<Core.Class>;
  bindShow: React.Dispatch<boolean>;
  selectedCategory?: string;
  /** Called with the new property's subject once it's saved onto the class. */
  onCreated?: (subject: string) => void;
}

/** Returns the isA classes and propVals a draft of the given category starts with. */
const getCategoryGenesisPropVals = (
  category: PropertyFormCategory | undefined,
): { isA: string | string[]; propVals: Record<string, unknown> } => {
  switch (category) {
    case 'number':
      return {
        isA: core.classes.property,
        propVals: { [core.properties.datatype]: Datatype.INTEGER },
      };
    case 'date':
      return {
        isA: core.classes.property,
        propVals: { [core.properties.datatype]: Datatype.DATE },
      };
    case 'checkbox':
      return {
        isA: core.classes.property,
        propVals: { [core.properties.datatype]: Datatype.BOOLEAN },
      };
    case 'file':
      return {
        isA: core.classes.property,
        propVals: {
          [core.properties.datatype]: Datatype.ATOMIC_URL,
          [core.properties.classtype]: server.classes.file,
        },
      };
    case 'json':
      return {
        isA: core.classes.property,
        propVals: { [core.properties.datatype]: Datatype.JSON },
      };
    case 'localizedText':
      return {
        isA: core.classes.property,
        propVals: { [core.properties.datatype]: Datatype.LOCALIZEDTEXT },
      };
    case 'select':
      return {
        isA: [core.classes.property, dataBrowser.classes.selectProperty],
        propVals: {
          [core.properties.datatype]: Datatype.RESOURCEARRAY,
          [core.properties.classtype]: dataBrowser.classes.tag,
          [core.properties.allowsOnly]: [],
        },
      };
    case 'relation':
      return {
        isA: core.classes.property,
        propVals: { [core.properties.datatype]: Datatype.ATOMIC_URL },
      };
    case 'text':
    default:
      return {
        isA: core.classes.property,
        propVals: { [core.properties.datatype]: Datatype.STRING },
      };
  }
};

// Fields the dialog passes on separately. The constraint fields (options,
// linked class, limits) go to the table class's `constraints` map, not to the
// immutable Property.
const FORM_HANDLED_KEYS = [
  core.properties.name,
  core.properties.shortname,
  core.properties.description,
  core.properties.datatype,
  ...CONSTRAINT_FIELDS,
];

/** The tags the user added to a select draft, as seeds for the real property. */
const tagSeedsFromDraft = async (
  store: ReturnType<typeof useStore>,
  draft: Resource,
): Promise<TagSeed[]> => {
  const subjects = draft.getSubjects(core.properties.allowsOnly);
  const seeds: TagSeed[] = [];

  for (const subject of subjects) {
    const tag = await store.getResource(subject);
    const text =
      (tag.get(core.properties.name) as string | undefined) ??
      (tag.get(core.properties.shortname) as string | undefined);

    if (!text) {
      continue;
    }

    seeds.push({
      name: text,
      color: tag.get(dataBrowser.properties.color) as string | undefined,
      emoji: tag.get(dataBrowser.properties.emoji) as string | undefined,
    });
  }

  return seeds;
};

export function NewPropertyDialog({
  showDialog,
  selectedCategory,
  tableClassResource,
  bindShow,
  onCreated,
}: NewPropertyDialogProps): JSX.Element {
  const store = useStore();
  // Form state only. The draft is never saved: the content-addressed property
  // is created on confirm, once its shortname and datatype are final.
  const [propertyResource, setPropertyResource] = useState<Resource | null>(
    null,
  );
  const [valid, setValid] = useState(true);

  const createProperty = useCallback(
    async (draft: Resource) => {
      const name = (draft.get(core.properties.name) as string) ?? '';
      const shortname = stringToSlug(name.trim()) || 'column';
      const datatype = draft.get(core.properties.datatype) as Datatype;
      // A new column is always a new property: never reuse another column's.
      const naming = { name, shortname, reuse: false };

      if (selectedCategory === 'select') {
        const max = draft.get(dataBrowser.properties.max) as number | undefined;
        const { subject } = await createSelectPropertyOnClass(
          store,
          tableClassResource,
          { ...naming, tags: await tagSeedsFromDraft(store, draft), max },
        );

        return subject;
      }

      const { isA, propVals } = copyablePropertyFields(draft);

      for (const key of FORM_HANDLED_KEYS) {
        delete propVals[key];
      }

      return createPropertyOnClass(store, tableClassResource, {
        ...naming,
        datatype,
        constraint: constraintPatchFromDraft(draft),
        description: (draft.get(core.properties.description) as string) ?? '',
        // The range class only marked properties that carried `min` / `max`.
        classes: isA.filter(
          c =>
            c !== core.classes.property &&
            c !== dataBrowser.classes.rangeProperty,
        ),
        propVals,
      });
    },
    [store, tableClassResource, selectedCategory],
  );

  const onSuccess = useCallback(async () => {
    if (!propertyResource) {
      return;
    }

    const subject = await createProperty(propertyResource);
    onCreated?.(subject);
  }, [propertyResource, createProperty, onCreated]);

  const [dialogProps, show, hide] = useDialog({ bindShow, onSuccess });

  useEffect(() => {
    if (!showDialog) {
      setPropertyResource(null);

      return;
    }

    const init = async () => {
      // The draft sits under the same parent the property will get.
      const tableClassParent = await store.getResource(
        tableClassResource.props.parent,
      );
      const parentSubject = tableClassParent.hasClasses(core.classes.ontology)
        ? tableClassParent.subject
        : tableClassResource.subject;

      const name = 'column';
      const { isA, propVals } = getCategoryGenesisPropVals(
        selectedCategory as PropertyFormCategory,
      );

      const draft = await createPropertyDraft(store, parentSubject, {
        isA,
        propVals: {
          [core.properties.name]: name,
          [core.properties.description]: '',
          ...(propVals as Record<string, JSONValue>),
        },
      });

      setPropertyResource(draft);
      // show() is called in a separate effect after propertyResource is set,
      // so the Dialog is already in the DOM when show() runs.
    };

    init().catch(console.error);
  }, [showDialog]);

  // Open dialog after propertyResource is set and Dialog is mounted.
  useEffect(() => {
    if (propertyResource && showDialog) {
      show();
    }
  }, [propertyResource]);

  const handleCreateClick = useCallback(() => {
    hide(true);
  }, [hide]);

  return (
    <FormValidationContextProvider onValidationChange={setValid}>
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>
            New{' '}
            {selectedCategory
              ? selectedCategory[0].toUpperCase() + selectedCategory.slice(1)
              : ''}{' '}
            Column
          </h1>
        </DialogTitle>
        <DialogContent>
          {propertyResource && (
            <PropertyForm
              resource={propertyResource}
              category={selectedCategory as PropertyFormCategory}
              onSubmit={handleCreateClick}
              autoFocusName
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCreateClick} disabled={!valid}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </FormValidationContextProvider>
  );
}
