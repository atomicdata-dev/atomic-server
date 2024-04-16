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
import { Panel, usePanelList } from '../components/SideBar/usePanelList';

export const SettingsTheme: React.FunctionComponent = () => {
  const {
    darkModeSetting,
    setDarkMode,
    viewTransitionsDisabled,
    setViewTransitionsDisabled,
    sidebarKeyboardDndEnabled,
    setSidebarKeyboardDndEnabled,
  } = useSettings();

  const { enabledPanels, enablePanel, disablePanel } = usePanelList();

  const changePanelPref = (panel: Panel) => (state: boolean) => {
    if (state) {
      enablePanel(panel);
    } else {
      disablePanel(panel);
    }
  };

  return (
    <Main>
      <ContainerNarrow>
        <h1>Settings</h1>
        <Column>
          <Heading>Theme</Heading>
          <Row>
            <Button
              subtle={!(darkModeSetting === DarkModeOption.auto)}
              onClick={() => setDarkMode(undefined)}
              title="Use the browser's / OS dark mode settings"
            >
              🌓 Auto
            </Button>
            <Button
              subtle={!(darkModeSetting === DarkModeOption.always)}
              onClick={() => setDarkMode(true)}
            >
              🌑 Dark
            </Button>
            <Button
              subtle={!(darkModeSetting === DarkModeOption.never)}
              onClick={() => setDarkMode(false)}
            >
              🌕 Light
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
          <Heading>Panels</Heading>
          <CheckboxLabel>
            <Checkbox
              checked={enabledPanels.has(Panel.Ontologies)}
              onChange={changePanelPref(Panel.Ontologies)}
            />{' '}
            Enable Ontology panel
          </CheckboxLabel>
          <Heading>Accessibility</Heading>
          <CheckboxLabel>
            <Checkbox
              checked={viewTransitionsDisabled}
              onChange={checked => setViewTransitionsDisabled(checked)}
            />{' '}
            Disable page transition animations
          </CheckboxLabel>
          <CheckboxLabel>
            <Checkbox
              checked={sidebarKeyboardDndEnabled}
              onChange={checked => setSidebarKeyboardDndEnabled(checked)}
            />{' '}
            Enable keyboard drag & drop in sidebar
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
