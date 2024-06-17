import { useState } from 'react';
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
  const [error, setError] = useState<Error | undefined>(undefined);
  const [subject, setSubject] = useSubject(resource, property.subject, {
    handleValidationError: setError,
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
        error={error}
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
