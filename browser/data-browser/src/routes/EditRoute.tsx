import { useState } from 'react';
import { useNavigate } from 'react-router';
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

  const handleBackClick = () => {
    navigate(constructOpenURL(subject ?? ''));
  };

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
                onClick={handleBackClick}
              >
                <FaArrowLeft />
              </IconButton>
              <Title resource={resource} prefix='Edit' />
            </Row>
            <ClassDetail resource={resource} />
            {/* Key is required for re-rendering when subject changes */}
            <ResourceForm resource={resource} key={subject} />
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
