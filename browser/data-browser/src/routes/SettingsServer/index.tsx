import * as React from 'react';
import { Button } from '../../components/Button';
import {
  ErrMessage,
  FieldStyled,
  InputStyled,
  InputWrapper,
  LabelStyled,
} from '../../components/forms/InputStyles';
import { useState } from 'react';
import { useSettings } from '../../helpers/AppSettings';
import { ContainerWide } from '../../components/Containers';
import { Row } from '../../components/Row';
import { useDriveHistory } from '../../hooks/useDriveHistory';
import { DrivesCard } from './DrivesCard';
import styled from 'styled-components';
import { useSavedDrives } from '../../hooks/useSavedDrives';
import { constructOpenURL } from '../../helpers/navigation';
import { useNavigate } from 'react-router';

export function SettingsServer(): JSX.Element {
  const { drive: baseURL, setDrive: setBaseURL } = useSettings();
  const navigate = useNavigate();
  const [baseUrlInput, setBaseUrlInput] = useState<string>(baseURL);
  const [baseUrlErr, setErrBaseUrl] = useState<Error | undefined>();

  const [savedDrives] = useSavedDrives();

  const [history, addDriveToHistory] = useDriveHistory(savedDrives);

  function handleSetBaseUrl(url: string) {
    try {
      setBaseURL(url);
      setBaseUrlInput(url);
      addDriveToHistory(url);
      navigate(constructOpenURL(url));
    } catch (e) {
      setErrBaseUrl(e);
    }
  }

  return (
    <ContainerWide>
      <Heading>Drive Configuration</Heading>
      <FieldStyled>
        <LabelStyled>Current Drive</LabelStyled>
        <Row>
          <InputWrapper>
            <InputStyled
              data-test='server-url-input'
              value={baseUrlInput}
              onChange={e => setBaseUrlInput(e.target.value)}
            />
          </InputWrapper>
          <Button
            onClick={() => handleSetBaseUrl(baseUrlInput)}
            disabled={baseURL === baseUrlInput}
            data-test='server-url-save'
          >
            Save
          </Button>
        </Row>
      </FieldStyled>
      <ErrMessage>{baseUrlErr?.message}</ErrMessage>
      <Heading as='h2'>Saved</Heading>
      <DrivesCard
        showNewOption
        drives={savedDrives}
        onDriveSelect={subject => handleSetBaseUrl(subject)}
      />
      <Heading as='h2'>Other</Heading>
      <DrivesCard
        drives={history}
        onDriveSelect={subject => handleSetBaseUrl(subject)}
      />
    </ContainerWide>
  );
}

const Heading = styled.h1`
  margin: 0;
  margin-bottom: 1rem;
`;
