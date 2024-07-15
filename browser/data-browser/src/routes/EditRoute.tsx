import { useCallback, useEffect, useState } from 'react';
import { useResource } from '@tomic/react';
import { constructOpenURL, newURL } from '../helpers/navigation';
import { ContainerNarrow } from '../components/Containers';
import { InputStyled } from '../components/forms/InputStyles';
import { ResourceForm } from '../components/forms/ResourceForm';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { ClassDetail } from '../components/ClassDetail';
import { Title } from '../components/Title';
import { Main } from '../components/Main';
import { Column, Row } from '../components/Row';
import { IconButton } from '../components/IconButton/IconButton';
import { FaArrowLeft } from 'react-icons/fa';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';

/** Form for instantiating a new Resource from some Class */
export function Edit(): JSX.Element {
  const [subject] = useCurrentSubject();
  const resource = useResource(subject);
  const [subjectInput, setSubjectInput] = useState<string | undefined>(
    undefined,
  );
  const navigate = useNavigateWithTransition();

  const handleClassSet: React.FormEventHandler<HTMLFormElement> = e => {
    e.preventDefault();

    if (!subjectInput) {
      throw new Error('No subject input');
    }

    navigate(newURL(subjectInput));
  };

  const cancelEdit = useCallback(() => {
    navigate(constructOpenURL(subject ?? ''));
  }, [subject, navigate]);

  useEffect(
    () => () => {
      resource.refresh();
    },
    [],
  );

  return (
    <Main subject={subject}>
      <ContainerNarrow>
        {subject ? (
          <Column>
            <Row center gap='1ch'>
              <IconButton
                title={`Back to ${resource.title}`}
                size='1.4em'
                edgeAlign='start'
                onClick={cancelEdit}
              >
                <FaArrowLeft />
              </IconButton>
              <Title resource={resource} prefix='Edit' />
            </Row>
            <ClassDetail resource={resource} />
            {/* Key is required for re-rendering when subject changes */}
            <ResourceForm
              resource={resource}
              key={subject}
              onCancel={cancelEdit}
            />
          </Column>
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
      </ContainerNarrow>
    </Main>
  );
}
