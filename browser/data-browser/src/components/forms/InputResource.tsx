import React, { useState } from 'react';
import { InputProps } from './ResourceField';
import { noNestedSupport, useSubject } from '@tomic/react';
import { ResourceSelector } from './ResourceSelector';
import { ErrorLook } from '../ErrorLook';

/** Input field for a single Resource. Renders a dropdown select menu. */
export function InputResource({
  resource,
  property,
  ...props
}: InputProps): JSX.Element {
  const [error, setError] = useState<Error | undefined>(undefined);
  const [subject, setSubject] = useSubject(resource, property.subject, {
    handleValidationError: setError,
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
        classType={property.classType}
        setSubject={setSubject}
        value={subject}
        parent={resource.getSubject()}
        {...props}
      />
    </div>
  );
}
