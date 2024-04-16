import { Datatype, server } from '@tomic/react';

import { InputProps } from './ResourceField';
import InputString from './InputString';
import { InputResource } from './InputResource';
import InputResourceArray from './InputResourceArray';
import InputMarkdown from './InputMarkdown';
import InputNumber from './InputNumber';
import InputBoolean from './InputBoolean';
import InputSlug from './InputSlug';
import { InputTimestamp } from './InputTimestamp';
import { InputDate } from './InputDate';
import { FilePicker } from './FilePicker/FilePicker';

/** Renders a fitting HTML input depending on the Datatype */
export default function InputSwitcher(props: InputProps): JSX.Element {
  switch (props.property.datatype) {
    case Datatype.STRING: {
      return <InputString {...props} />;
    }

    case Datatype.MARKDOWN: {
      return <InputMarkdown {...props} />;
    }

    case Datatype.SLUG: {
      return <InputSlug {...props} />;
    }

    case Datatype.INTEGER: {
      return <InputNumber {...props} />;
    }

    case Datatype.FLOAT: {
      return <InputNumber {...props} />;
    }

    case Datatype.ATOMIC_URL: {
      if (props.property.classType === server.classes.file) {
        return <FilePicker {...props} />;
      }

      return <InputResource {...props} />;
    }

    case Datatype.RESOURCEARRAY: {
      return <InputResourceArray {...props} />;
    }

    case Datatype.BOOLEAN: {
      return <InputBoolean {...props} />;
    }

    case Datatype.TIMESTAMP: {
      return <InputTimestamp {...props} />;
    }

    case Datatype.DATE: {
      return <InputDate {...props} />;
    }

    default: {
      return <InputString {...props} />;
    }
  }
}
