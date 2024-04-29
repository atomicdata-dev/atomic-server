import { JSONValue, Resource } from '@tomic/react';

export interface EditCellProps<T extends JSONValue> {
  value: T;
  onChange: (value: T) => void;
  property: string;
  resource: Resource;
}

export interface DisplayCellProps<T extends JSONValue> {
  value: T;
  onChange: (value: T) => void;
  property: string;
}

export type CellContainer<T extends JSONValue> = {
  Edit: (props: EditCellProps<T>) => JSX.Element;
  Display: (props: DisplayCellProps<T>) => JSX.Element;
};

export interface ResourceCellProps {
  subject: string;
}
