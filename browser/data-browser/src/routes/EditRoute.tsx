import React, { useState } from 'react';
import { useNavigate } from 'react-router';
import { useResource } from '@tomic/react';
import { newURL } from '../helpers/navigation';
import { ContainerNarrow } from '../components/Containers';
import { InputStyled } from '../components/forms/InputStyles';
import { ResourceForm } from '../components/forms/ResourceForm';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { ClassDetail } from '../components/ClassDetail';
import { Title } from '../components/Title';
import Parent from '../components/Parent';
import { Main } from '../components/Main';

/** Form for instantiating a new Resource from some Class */
export function Edit(): JSX.Element {
  const [subject] = useCurrentSubject();
  const resource = useResource(subject);
  const [subjectInput, setSubjectInput] = useState<string | undefined>(
    undefined,
  );
  const navigate = useNavigate();

  function handleClassSet(e) {
    e.preventDefault();

    if (!subjectInput) {
      throw new Error('No subject input');
    }

    navigate(newURL(subjectInput));
  }

  return (
    <>
      <Parent resource={resource} />
      <ContainerNarrow>
        <Main subject={subject}>
          {subject ? (
            <>
              <Title resource={resource} prefix='Edit' />
              <ClassDetail resource={resource} />
              {/* Key is required for re-rendering when subject changes */}
              <ResourceForm resource={resource} key={subject} />
            </>
          ) : (
            <form onSubmit={handleClassSet}>
              <h1>edit a resource</h1>
              <InputStyled
                value={subjectInput || undefined}
                onChange={e => setSubjectInput(e.target.value)}
                placeholder={'Enter a Resource URL...'}
              />
            </form>
          )}
        </Main>
      </ContainerNarrow>
    </>
  );
}
