import { useResource } from '@tomic/react';
import { useQueryString } from '../../../helpers/navigation';
import { ResourceForm } from '../ResourceForm';
import { NewFormTitle } from './NewFormTitle';
import { SubjectField } from './SubjectField';
import { useNewForm } from './useNewForm';
import React from 'react';

export interface NewFormProps {
  classSubject: string;
}

/** Fullpage Form for instantiating a new Resource from some Class */
export const NewFormFullPage = ({
  classSubject,
}: NewFormProps): JSX.Element => {
  const klass = useResource(classSubject);
  const [subject, setSubject] = useQueryString('newSubject');
  const [parentSubject] = useQueryString('parent');

  const { subjectErr, subjectValue, setSubjectValue, resource } = useNewForm({
    klass,
    setSubject,
    initialSubject: subject,
    parent: parentSubject,
  });

  return (
    <>
      <NewFormTitle classSubject={classSubject} />
      <SubjectField
        error={subjectErr}
        value={subjectValue}
        onChange={setSubjectValue}
      />
      {/* Key is required for re-rendering when subject changes */}
      <ResourceForm
        resource={resource}
        classSubject={classSubject}
        key={`${classSubject}+${subject}`}
      />
    </>
  );
};
