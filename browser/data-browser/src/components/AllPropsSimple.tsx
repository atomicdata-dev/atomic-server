import {
  datatypes,
  AtomicValue,
  properties,
  Resource,
  useResource,
  useSubject,
  useTitle,
} from '@tomic/react';
import { useMemo, type JSX } from 'react';
import { styled } from 'styled-components';
import { InlineFormattedResourceList } from './InlineFormattedResourceList';
import { isNeverEditableProp } from '../helpers/hiddenProperties';
import { asSubject, formatPlainValue } from '../helpers/formatPlainValue';

export interface AllPropsSimpleProps {
  resource: Resource;
}

/** Renders a simple list of all properties on the resource. Will not render any link or other interactive element. */
export function AllPropsSimple({ resource }: AllPropsSimpleProps): JSX.Element {
  return (
    <ul>
      {resource
        .getEntries()
        .filter(
          ([prop, val]) =>
            !(val instanceof Uint8Array) && !isNeverEditableProp(prop),
        )
        .map(([prop, val]) => (
          <Row key={prop} prop={prop} val={val} />
        ))}
    </ul>
  );
}

interface RowProps {
  prop: string;
  val: AtomicValue;
}

function Row({ prop, val }: RowProps): JSX.Element {
  const propResource = useResource(prop);
  const [propName] = useTitle(propResource);
  const [dataType] = useSubject(propResource, properties.datatype);

  const value = useMemo(() => {
    // Only a string can be looked up. Anything else (a nested object, a
    // number) falls through to plain text, never to a raw React child.
    if (dataType === datatypes.atomicUrl && asSubject(val)) {
      return <Value subject={val as string} />;
    }

    if (dataType === datatypes.resourceArray && Array.isArray(val)) {
      return (
        <InlineFormattedResourceList
          subjects={val as string[]}
          RenderComp={Value}
        />
      );
    }

    return <>{formatPlainValue(val)}</>;
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

function Value({ subject }: { subject: string }): JSX.Element {
  const valueResource = useResource(subject);
  const [valueName] = useTitle(valueResource);

  return <>{valueName}</>;
}
