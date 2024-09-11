import { useResource, core } from '@tomic/react';
import { useCallback } from 'react';
import { useNavigate } from 'react-router';

import { constructOpenURL, useQueryString } from '../../helpers/navigation';
import {
  ContainerFull,
  ContainerNarrow,
  ContainerWide,
} from '../../components/Containers';
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
import { Column } from '../../components/Row';
import { TemplateList } from '../../components/Template/TemplateList';

/** Start page for instantiating a new Resource from some Class */
function NewRoute(): JSX.Element {
  const [classSubject] = useQueryString('classSubject');

  return (
    <Main>
      {classSubject ? (
        <ContainerNarrow>
          <NewFormFullPage classSubject={classSubject.toString()} />
        </ContainerNarrow>
      ) : (
        <ContainerFull>
          <NewResourceSelector />
        </ContainerFull>
      )}
    </Main>
  );
}

function NewResourceSelector() {
  const [parentSubject] = useQueryString('parentSubject');
  const { drive, hideTemplates } = useSettings();
  const calculatedParent = parentSubject || drive;
  const parentResource = useResource(calculatedParent);

  const showTemplates = !hideTemplates && calculatedParent === drive;
  const Container = showTemplates ? ContainerWide : ContainerNarrow;

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

      if (calculatedParent) {
        navigate(constructOpenURL(calculatedParent));
      }
    },
    [parentSubject, navigate],
  );

  return (
    <Container>
      <Column gap='2rem'>
        <h1>
          Create new resource{' '}
          {calculatedParent && (
            <>
              {`under `}
              <ResourceInline subject={calculatedParent} />
            </>
          )}
        </h1>
        <SideBySide noTemplates={!showTemplates}>
          <Column gap='2rem'>
            <h2>Classes</h2>
            <div>
              <ResourceSelector
                hideCreateOption
                setSubject={handleClassSet}
                isA={core.classes.class}
              />
            </div>
            <BaseButtons parent={calculatedParent} />
            <OntologySections parent={calculatedParent} />
            <FileDropzoneInput
              parentResource={parentResource}
              onFilesUploaded={onUploadComplete}
            />
          </Column>
          {showTemplates && (
            <>
              <Devider />
              <Column>
                <h2>Templates</h2>
                <TemplateList />
              </Column>
            </>
          )}
        </SideBySide>
      </Column>
    </Container>
  );
}

const SideBySide = styled.div<{ noTemplates: boolean }>`
  display: grid;
  grid-template-columns: ${p => (p.noTemplates ? '1fr' : '2.5fr 1px 1fr')};
  gap: 2rem;

  @container (max-width: 700px) {
    grid-template-columns: 1fr;
  }
`;

const Devider = styled.div`
  border-right: 1px solid ${p => p.theme.colors.bg2};
`;

export default NewRoute;
