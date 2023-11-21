import {
  Datatype,
  valToDate,
  valToString,
  valToArray,
  valToResource,
  JSONValue,
} from '@tomic/react';
import { ResourceInline } from '../views/ResourceInline';
import { DateTime } from './datatypes/DateTime';
import Markdown from './datatypes/Markdown';
import Nestedresource from './datatypes/NestedResource';
import ResourceArray from './datatypes/ResourceArray';
import { ErrMessage } from './forms/InputStyles';

type Props = {
  value: JSONValue;
  datatype: Datatype;
  noMargin?: boolean;
};

/** Renders a value in a fitting way, depending on its DataType */
function ValueComp({ value, datatype, noMargin }: Props): JSX.Element {
  try {
    switch (datatype) {
      case Datatype.ATOMIC_URL: {
        const resource = valToResource(value);

        if (typeof resource === 'string') {
          return <ResourceInline subject={resource} />;
        }

        return <Nestedresource resource={resource} />;
      }

      case (Datatype.DATE, Datatype.TIMESTAMP):
        return <DateTime date={valToDate(value)} />;
      case Datatype.MARKDOWN:
        return <Markdown text={valToString(value)} noMargin={noMargin} />;
      case Datatype.RESOURCEARRAY:
        return <ResourceArray subjects={valToArray(value)} />;
      default:
        return <div>{valToString(value)}</div>;
    }
  } catch (e) {
    return (
      <ErrMessage>
        {e.message} original value: {value?.toString()}
      </ErrMessage>
    );
  }
}

export default ValueComp;
