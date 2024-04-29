import { Core, dataBrowser, Datatype, Resource, urls } from '@tomic/react';
import { CheckboxPropertyForm } from './CheckboxPropertyForm';
import { DatePropertyForm } from './DatePropertyForm';
import { FilePropertyForm } from './FilePropertyForm';
import { NumberPropertyForm } from './NumberPropertyForm';
import { RelationPropertyForm } from './RelationPropertyForm';
import { SelectPropertyForm } from './SelectPropertyForm';
import { TextPropertyForm } from './TextPropertyForm';
import { buildComponentFactory } from '../../../helpers/buildComponentFactory';

export type PropertyFormCategory =
  | 'text'
  | 'number'
  | 'date'
  | 'checkbox'
  | 'file'
  | 'select'
  | 'relation';

const TEXT_TYPES = new Set<string>([
  Datatype.STRING,
  Datatype.MARKDOWN,
  Datatype.SLUG,
]);
const NUMBER_TYPES = new Set<string>([Datatype.INTEGER, Datatype.FLOAT]);
const DATE_TYPES = new Set<string>([Datatype.DATE, Datatype.TIMESTAMP]);

export const getCategoryFromResource = (
  resource: Resource<Core.Property>,
): PropertyFormCategory => {
  const datatype = resource.props.datatype;

  if (TEXT_TYPES.has(datatype)) {
    return 'text';
  }

  if (NUMBER_TYPES.has(datatype)) {
    return 'number';
  }

  if (datatype === Datatype.BOOLEAN) {
    return 'checkbox';
  }

  if (DATE_TYPES.has(datatype)) {
    return 'date';
  }

  if (datatype === Datatype.RESOURCEARRAY) {
    if (
      resource.props.classtype === dataBrowser.classes.tag ||
      resource.hasClasses(urls.classes.constraintProperties.selectProperty)
    ) {
      return 'select';
    }

    return 'relation';
  }

  if (datatype === Datatype.ATOMIC_URL) {
    return 'relation';
  }

  throw new Error(`Unknown datatype: ${datatype}`);
};

const NoCategorySelected = () => {
  return <span>No Type selected</span>;
};

export const categoryFormFactory = buildComponentFactory(
  new Map([
    ['text', TextPropertyForm],
    ['number', NumberPropertyForm],
    ['checkbox', CheckboxPropertyForm],
    ['select', SelectPropertyForm],
    ['date', DatePropertyForm],
    ['file', FilePropertyForm],
    ['relation', RelationPropertyForm],
  ]),
  NoCategorySelected,
);
