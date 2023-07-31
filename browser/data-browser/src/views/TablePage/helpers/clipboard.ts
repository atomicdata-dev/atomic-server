import {
  Datatype,
  JSONValue,
  properties,
  Property,
  Resource,
  Store,
} from '@tomic/react';
import { CopyValue } from '../../../components/TableEditor';

const getTitle = (resource: Resource): string => {
  return (resource.get(properties.name) ??
    resource.get(properties.file.filename) ??
    resource.get(properties.shortname) ??
    resource.getSubject()) as string;
};

const jsonValueToString = (value: JSONValue): string => {
  if (Array.isArray(value)) {
    return value.join(', ');
  }

  return `${value ?? ''}`;
};

const createAtomicURLCopyValue = async (
  subject: string | undefined,
  store: Store,
): Promise<CopyValue> => {
  if (subject === undefined) {
    return {
      plain: '',
      html: '',
    };
  }

  const referenceResource = await store.getResourceAsync(subject as string);

  const title = getTitle(referenceResource);

  return {
    plain: title,
    html: `<a href="${subject}">${title}</a>`,
  };
};

const createResourceArrayCopyValue = async (
  array: string[] | undefined,
  store: Store,
): Promise<CopyValue> => {
  if (!array) {
    return {
      plain: '',
      html: '',
    };
  }

  const copyValues = await Promise.all(
    array.map(async subject => {
      return createAtomicURLCopyValue(subject, store);
    }),
  );

  return {
    plain: copyValues.map(v => v.plain).join(', '),
    html: copyValues.map(v => v.html).join(', '),
  };
};

const createCopyValueFromResourceProperty = async (
  resource: Resource,
  property: Property,
  store: Store,
): Promise<CopyValue> => {
  switch (property.datatype) {
    case Datatype.ATOMIC_URL:
      return createAtomicURLCopyValue(
        resource.get(property.subject) as string,
        store,
      );
    case Datatype.RESOURCEARRAY:
      return createResourceArrayCopyValue(
        resource.get(property.subject) as string[],
        store,
      );

    default: {
      const val = jsonValueToString(resource.get(property.subject));

      return {
        plain: val,
        html: val,
      };
    }
  }
};

export const getValuesFromSubject = async (
  subject: string,
  columns: Property[],
  store: Store,
): Promise<CopyValue[]> => {
  const resource = await store.getResourceAsync(subject);

  return Promise.all(
    columns.map(col =>
      createCopyValueFromResourceProperty(resource, col, store),
    ),
  );
};
