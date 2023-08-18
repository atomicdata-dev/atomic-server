import * as React from 'react';
import { ContainerNarrow } from '../components/Containers';
import { HexColorPicker } from 'react-colorful';
import { Button } from '../components/Button';
import { useSettings } from '../helpers/AppSettings';
import { NavStyleButton } from '../components/NavStyleButton';
import { DarkModeOption } from '../helpers/useDarkMode';
import { Column, Row } from '../components/Row';
import { styled } from 'styled-components';
import { Checkbox, CheckboxLabel } from '../components/forms/Checkbox';
import { Main } from '../components/Main';

export const SettingsTheme: React.FunctionComponent = () => {
  const {
    darkModeSetting,
    setDarkMode,
    viewTransitionsEnabled,
    setViewTransitionsEnabled,
  } = useSettings();

  return (
    <Main>
      <ContainerNarrow>
        <h1>Theme Settings</h1>
        <Column>
          <Heading>Dark mode</Heading>
          <Row>
            <Button
              subtle={!(darkModeSetting === DarkModeOption.auto)}
              onClick={() => setDarkMode(undefined)}
              title="Use the browser's / OS dark mode settings"
            >
              🌓 auto
            </Button>
            <Button
              subtle={!(darkModeSetting === DarkModeOption.always)}
              onClick={() => setDarkMode(true)}
            >
              🌑 on
            </Button>
            <Button
              subtle={!(darkModeSetting === DarkModeOption.never)}
              onClick={() => setDarkMode(false)}
            >
              🌕 off
            </Button>
          </Row>
          <Heading>Navigation bar position</Heading>
          <Row>
            <NavStyleButton floating={true} top={false} title='Floating' />
            <NavStyleButton floating={false} top={false} title='Bottom' />
            <NavStyleButton floating={false} top={true} title='Top' />
          </Row>
          <Heading>Main color</Heading>
          <MainColorPicker />
          <Heading>Animations</Heading>
          <CheckboxLabel>
            <Checkbox
              checked={viewTransitionsEnabled}
              onChange={checked => setViewTransitionsEnabled(checked)}
            />{' '}
            Enable view transitions
          </CheckboxLabel>
        </Column>
      </ContainerNarrow>
    </Main>
  );
};

const MainColorPicker = () => {
  const { mainColor, setMainColor } = useSettings();

  return (
    <HexColorPicker color={mainColor} onChange={val => setMainColor(val)} />
  );
};

const Heading = styled.h2`
  font-size: 1em;
  margin: 0;
  margin-top: 1rem;
`;
