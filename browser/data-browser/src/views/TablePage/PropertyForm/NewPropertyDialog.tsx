import { Resource, Store, urls, useArray, useStore } from '@tomic/react';
import React, { useCallback, useEffect, useState } from 'react';
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
import { PropertyForm, PropertyFormCategory } from './PropertyForm';

interface NewPropertyDialogProps {
  showDialog: boolean;
  tableClassResource: Resource;
  bindShow: React.Dispatch<boolean>;
  selectedCategory?: string;
}

const createSubjectWithBase = (base: string) => {
  const sepperator = base.endsWith('/') ? '' : '/';

  return `${base}${sepperator}property-${randomString(8)}`;
};

const populatePropertyWithDefaults = async (
  property: Resource,
  tableClass: Resource,
  store: Store,
) => {
  await property.set(urls.properties.isA, [urls.classes.property], store);
  await property.set(urls.properties.parent, tableClass.getSubject(), store);
  await property.set(urls.properties.shortname, 'new-column', store, false);
  await property.set(urls.properties.name, '', store, false);
  await property.set(urls.properties.description, 'A column in a table', store);
  await property.set(urls.properties.datatype, urls.datatypes.string, store);

  await property.save(store);
};

const getChildren = (store: Store, resource: Resource) =>
  store.clientSideQuery(
    res => res.get(urls.properties.parent) === resource?.getSubject(),
  );

const destroyChildren = async (store: Store, resource: Resource) => {
  const children = getChildren(store, resource);

  await Promise.all(
    children.map(child => {
      try {
        child.destroy(store);
      } catch (e) {
        return;
      }
    }),
  );
};

const saveChildren = async (store: Store, resource: Resource) => {
  const children = getChildren(store, resource);
  await Promise.all(children.map(child => child.save(store)));
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
    urls.properties.recommends,
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
      await resource.destroy(store);
    } finally {
      // Server does not have this resource yet so it will nag at us. We set the state to null anyway.
      setResource(null);
    }
  }, [resource, store]);

  const handleUserSuccessAction = useCallback(async () => {
    if (!resource) {
      return;
    }

    await resource.save(store);
    await saveChildren(store, resource);
    await store.notifyResourceManuallyCreated(resource);

    await pushProp([resource.getSubject()]);
    setResource(null);
  }, [resource, store, tableClassResource, pushProp]);

  const [dialogProps, show, hide] = useDialog({
    bindShow,
    onCancel: handleUserCancelAction,
    onSuccess: handleUserSuccessAction,
  });

  const createProperty = async () => {
    const subject = createSubjectWithBase(tableClassResource.getSubject());
    const propertyResource = store.getResourceLoading(subject, {
      newResource: true,
    });

    await populatePropertyWithDefaults(
      propertyResource,
      tableClassResource,
      store,
    );

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
