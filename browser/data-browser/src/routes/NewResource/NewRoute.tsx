import { useResource, urls } from '@tomic/react';
import { useCallback } from 'react';
import { useNavigate } from 'react-router';

import { constructOpenURL, useQueryString } from '../../helpers/navigation';
import { ContainerNarrow } from '../../components/Containers';
import { ResourceSelector } from '../../components/forms/ResourceSelector';
import { useSettings } from '../../helpers/AppSettings';
import { ResourceInline } from '../../views/ResourceInline';
import { styled } from 'styled-components';
import { FileDropzoneInput } from '../../components/forms/FileDropzone/FileDropzoneInput';
import toast from 'react-hot-toast';
import { NewFormFullPage } from '../../components/forms/NewForm/NewFormPage';
import { Main } from '../../components/Main';
import { BaseButtons } from './BaseButtons';
import { OntologySections } from './OntologySections';
import { useNewResourceUI } from '../../components/forms/NewForm/useNewResourceUI';

/** Start page for instantiating a new Resource from some Class */
function NewRoute(): JSX.Element {
  const [classSubject] = useQueryString('classSubject');

  return (
    <ContainerNarrow>
      {classSubject ? (
        <NewFormFullPage classSubject={classSubject.toString()} />
      ) : (
        <NewResourceSelector />
      )}
    </ContainerNarrow>
  );
}

function NewResourceSelector() {
  const [parentSubject] = useQueryString('parentSubject');
  const { drive } = useSettings();
  const calculatedParent = parentSubject || drive;
  const parentResource = useResource(calculatedParent);

  const navigate = useNavigate();
  const showNewResourceUI = useNewResourceUI();

  function handleClassSet(subject: string | undefined) {
    if (!subject) {
      return;
    }

    showNewResourceUI(subject, calculatedParent);
  }

  const onUploadComplete = useCallback(
    (files: string[]) => {
      toast.success(`Uploaded ${files.length} files.`);

      if (parentSubject) {
        navigate(constructOpenURL(parentSubject));
      }
    },
    [parentSubject, navigate],
  );

  return (
    <Main>
      <StyledForm>
        <h1>
          Create new resource{' '}
          {parentSubject && (
            <>
              {`under `}
              <ResourceInline subject={parentSubject} />
            </>
          )}
        </h1>
        <div>
          <ResourceSelector
            hideCreateOption
            setSubject={handleClassSet}
            isA={urls.classes.class}
          />
        </div>
        <BaseButtons parent={calculatedParent} />
        <OntologySections parent={calculatedParent} />
        <FileDropzoneInput
          parentResource={parentResource}
          onFilesUploaded={onUploadComplete}
        />
      </StyledForm>
    </Main>
  );
}

const StyledForm = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.margin * 2}rem;
`;

export default NewRoute;
