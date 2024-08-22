import {
  Core,
  Datatype,
  Resource,
  Store,
  core,
  useArray,
  useStore,
} from '@tomic/react';
import { useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { Button } from '../../../components/Button';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../../components/Dialog';
import { FormValidationContextProvider } from '../../../components/forms/formValidation/FormValidationContextProvider';
import { randomString } from '../../../helpers/randomString';
import { PropertyForm } from './PropertyForm';
import { PropertyFormCategory } from './categories';
import { sortSubjectList } from '../../OntologyPage/sortSubjectList';

interface NewPropertyDialogProps {
  showDialog: boolean;
  tableClassResource: Resource<Core.Class>;
  bindShow: React.Dispatch<boolean>;
  selectedCategory?: string;
}

const createSubjectWithBase = (base: string) => {
  const sepperator = base.endsWith('/') ? '' : '/';

  return `${base}${sepperator}property-${randomString(8)}`;
};

const populatePropertyWithDefaults = async (
  property: Resource,
  tableClass: Resource<Core.Class>,
) => {
  await property.set(core.properties.isA, [core.classes.property]);
  await property.set(core.properties.parent, tableClass.props.parent);
  await property.set(core.properties.shortname, 'new-column', false);
  await property.set(core.properties.name, '', false);
  await property.set(core.properties.description, 'A column in a table');
  await property.set(core.properties.datatype, Datatype.STRING);

  await property.save();
};

const getChildren = (store: Store, resource: Resource) =>
  store.clientSideQuery(
    res => res.get(core.properties.parent) === resource?.subject,
  );

const destroyChildren = async (store: Store, resource: Resource) => {
  const children = getChildren(store, resource);

  await Promise.all(
    children.map(child => {
      try {
        child.destroy();
      } catch (e) {
        return;
      }
    }),
  );
};

const saveChildren = async (store: Store, resource: Resource) => {
  const children = getChildren(store, resource);
  await Promise.all(children.map(child => child.save()));
};

export function NewPropertyDialog({
  showDialog,
  selectedCategory,
  tableClassResource,
  bindShow,
}: NewPropertyDialogProps): JSX.Element {
  const [valid, setValid] = useState(false);

  const store = useStore();
  const [resource, setResource] = useState<Resource | null>(null);
  const [_properties, _setProperties, pushProp] = useArray(
    tableClassResource,
    core.properties.recommends,
    {
      commit: true,
    },
  );

  const handleUserCancelAction = useCallback(async () => {
    if (!resource) {
      return;
    }

    try {
      await destroyChildren(store, resource);
      await resource.destroy();
    } finally {
      // Server does not have this resource yet so it will nag at us. We set the state to null anyway.
      setResource(null);
    }
  }, [resource, store]);

  const handleUserSuccessAction = useCallback(async () => {
    if (!resource) {
      return;
    }

    const tableClassParent = await store.getResource(
      tableClassResource.props.parent,
    );

    if (tableClassParent.hasClasses(core.classes.ontology)) {
      await resource.set(core.properties.parent, tableClassParent.subject);

      const ontologyProps =
        tableClassParent.get(core.properties.properties) ?? [];

      await tableClassParent.set(
        core.properties.properties,
        await sortSubjectList(store, [...ontologyProps, resource.subject]),
      );

      await tableClassParent.save();
    }

    await resource.save();
    await saveChildren(store, resource);

    pushProp([resource.subject]);
    setResource(null);
  }, [resource, store, tableClassResource, pushProp]);

  const {
    dialogProps,
    show,
    close: hide,
  } = useDialog({
    bindShow,
    onCancel: handleUserCancelAction,
    onSuccess: handleUserSuccessAction,
  });

  const createProperty = async () => {
    const subject = createSubjectWithBase(tableClassResource.subject);
    const propertyResource = store.getResourceLoading(subject, {
      newResource: true,
    });

    await populatePropertyWithDefaults(propertyResource, tableClassResource);

    setResource(propertyResource);
  };

  const handleCancelClick = useCallback(() => {
    hide();
  }, [hide]);

  const handleCreateClick = useCallback(() => {
    if (valid) {
      hide(true);
    }
  }, [hide, valid]);

  useEffect(() => {
    if (showDialog) {
      createProperty().then(() => {
        show();
      });
    }
  }, [showDialog]);

  if (!resource) {
    return <></>;
  }

  return (
    <FormValidationContextProvider onValidationChange={setValid}>
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>
            New <Capitalize>{selectedCategory}</Capitalize> Column
          </h1>
        </DialogTitle>
        <DialogContent>
          <PropertyForm
            resource={resource}
            category={selectedCategory as PropertyFormCategory}
            onSubmit={handleCreateClick}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCancelClick} subtle>
            Cancel
          </Button>
          <Button onClick={handleCreateClick} disabled={!valid} type='submit'>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </FormValidationContextProvider>
  );
}

const Capitalize = styled('span')`
  text-transform: capitalize;
`;
