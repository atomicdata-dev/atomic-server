import { InputProps } from './ResourceField';
import { noNestedSupport, useSubject } from '@tomic/react';
import { ResourceSelector } from './ResourceSelector';
import { ErrorLook } from '../ErrorLook';

/** Input field for a single Resource. Renders a dropdown select menu. */
export function InputResource({
  resource,
  property,
  commit,
  ...props
}: InputProps): JSX.Element {
  const [subject, setSubject] = useSubject(resource, property.subject, {
    commit,
  });

  if (subject === noNestedSupport) {
    return (
      <ErrorLook>
        Sorry, there is no support for editing nested resources yet
      </ErrorLook>
    );
  }

  return (
    <div>
      <ResourceSelector
        isA={property.classType}
        setSubject={setSubject}
        value={subject}
        allowsOnly={property.allowsOnly}
        parent={resource.subject}
        {...props}
      />
    </div>
  );
}
