import {
  datatypes,
  JSONValue,
  properties,
  Resource,
  useResource,
  useSubject,
  useTitle,
} from '@tomic/react';
import React, { useMemo } from 'react';
import { styled } from 'styled-components';

export interface AllPropsSimpleProps {
  resource: Resource;
}

/** Renders a simple list of all properties on the resource. Will not render any link or other interactive element. */
export function AllPropsSimple({ resource }: AllPropsSimpleProps): JSX.Element {
  return (
    <ul>
      {[...resource.getPropVals()].map(([prop, val]) => (
        <Row key={prop} prop={prop} val={val} />
      ))}
    </ul>
  );
}

interface RowProps {
  prop: string;
  val: JSONValue;
}

function Row({ prop, val }: RowProps): JSX.Element {
  const propResource = useResource(prop);
  const [propName] = useTitle(propResource);
  const [dataType] = useSubject(propResource, properties.datatype);

  const value = useMemo(() => {
    if (dataType === datatypes.atomicUrl) {
      return <Value val={val as string} />;
    }

    if (dataType === datatypes.resourceArray) {
      return <ResourceArray val={val as string[]} />;
    }

    return <>{val as string}</>;
  }, [val, dataType]);

  return (
    <List>
      <Key>{propName}</Key>: {value}
    </List>
  );
}

const Key = styled.span`
  font-weight: bold;
`;

const List = styled.ul`
  list-style: none;
  margin: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  color: ${p => p.theme.colors.textLight};
`;

function ResourceArray({ val }: { val: string[] }): JSX.Element {
  return (
    <>
      {val.map((v, i) => (
        <>
          <Value val={v} key={v} />
          {i === val.length - 1 ? '' : ', '}
        </>
      ))}
    </>
  );
}

function Value({ val }: { val: string }): JSX.Element {
  const valueResource = useResource(val);
  const [valueName] = useTitle(valueResource);

  return <>{valueName}</>;
}
