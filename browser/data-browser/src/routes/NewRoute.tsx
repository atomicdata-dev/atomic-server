import { useResource, useString, useTitle, urls } from '@tomic/react';
import React, { useCallback, useState } from 'react';
import { useNavigate } from 'react-router';

import {
  constructOpenURL,
  newURL,
  useQueryString,
} from '../helpers/navigation';
import { ContainerNarrow } from '../components/Containers';
import NewIntanceButton from '../components/NewInstanceButton';
import { ResourceSelector } from '../components/forms/ResourceSelector';
import { Button } from '../components/Button';
import { useSettings } from '../helpers/AppSettings';
import { Row } from '../components/Row';
import { ResourceInline } from '../views/ResourceInline';
import styled from 'styled-components';
import { FileDropzoneInput } from '../components/forms/FileDropzone/FileDropzoneInput';
import toast from 'react-hot-toast';
import { getIconForClass } from '../views/FolderPage/iconMap';
import { NewFormFullPage } from '../components/forms/NewForm/NewFormPage';
import { Main } from '../components/Main';

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
  const [error, setError] = useState<Error | undefined>(undefined);
  const [classInputValue, setClassInputValue] = useState<string | undefined>();
  const classFull = useResource(classInputValue);
  const [className] = useString(classFull, urls.properties.shortname);
  const navigate = useNavigate();

  const buttons = [
    urls.classes.table,
    urls.classes.folder,
    urls.classes.document,
    urls.classes.chatRoom,
    urls.classes.bookmark,
  ];

  function handleClassSet(e) {
    if (!classInputValue) {
      setError(new Error('Please select a class'));

      return;
    }

    e.preventDefault();
    navigate(newURL(classInputValue, calculatedParent));
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
      <StyledForm onSubmit={handleClassSet}>
        <h1>
          Create new resource{' '}
          {parentSubject && (
            <>
              {`under `}
              <ResourceInline subject={parentSubject} />
            </>
          )}
        </h1>
        <Row wrapItems>
          {classInputValue && (
            <Button onClick={handleClassSet}>new {className}</Button>
          )}
          {!classInputValue && (
            <>
              {buttons.map(classType => (
                <WrappedButton
                  key={classType}
                  classType={classType}
                  parent={calculatedParent}
                />
              ))}
            </>
          )}
        </Row>
        <div>
          <ResourceSelector
            setSubject={setClassInputValue}
            value={classInputValue}
            error={error}
            classType={urls.classes.class}
          />
        </div>
        <FileDropzoneInput
          parentResource={parentResource}
          onFilesUploaded={onUploadComplete}
        />
      </StyledForm>
    </Main>
  );
}

const StyledForm = styled.form`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.margin}rem;
`;

export default NewRoute;

interface WrappedButtonProps {
  classType: string;
  parent: string;
}

function WrappedButton({ classType, parent }: WrappedButtonProps): JSX.Element {
  const classResource = useResource(classType);
  const [label] = useTitle(classResource);

  return (
    <NewIntanceButton
      icon
      IconComponent={getIconForClass(classType)}
      klass={classType}
      parent={parent}
      label={label}
      subtle
    />
  );
}
