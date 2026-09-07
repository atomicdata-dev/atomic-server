import * as React from 'react';
import { useState, useMemo } from 'react';
import { createRoute } from '@tanstack/react-router';
import { HexColorPicker } from 'react-colorful';
import { ContainerNarrow } from '../components/Containers';
import { Button } from '../components/Button';
import { useSettings } from '../helpers/AppSettings';
import { DarkModeOption } from '../helpers/useDarkMode';
import { Column, Row } from '../components/Row';
import { Checkbox, CheckboxLabel } from '../components/forms/Checkbox';
import { Main } from '../components/Main';
import { Panel, usePanelList } from '../components/SideBar/usePanelList';
import { pathNames } from './paths';
import { appRoute } from './RootRoutes';
import AISettings from '@components/AI/AISettings';
import { VirtualDriveSettings } from '@components/Settings/VirtualDriveSettings';
import { isVirtualDriveAvailable } from '../helpers/virtualDrive';
import { SUPPORTED_LOCALES, useLocale } from '@components/LocaleContext';
import { BasicSelect } from '@components/forms/BasicSelect';
import { styled } from 'styled-components';
import {
  SettingsGroup,
  SettingsSection,
  SettingsSearchProvider,
} from '@components/Settings';
import { presetColors } from '../styling';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { FaMagnifyingGlass, FaXmark } from 'react-icons/fa6';

export const AppSettingsRoute = createRoute({
  path: pathNames.appSettings,
  component: () => <AppSettings />,
  getParentRoute: () => appRoute,
});

const getLocaleName = (locale: string) => {
  const names = new Intl.DisplayNames([locale], { type: 'language' });

  return names.of(locale);
};

const AppSettings: React.FunctionComponent = () => {
  const {
    darkModeSetting,
    setDarkMode,
    colorfulMode,
    setColorfulMode,
    viewTransitionsDisabled,
    setViewTransitionsDisabled,
    sidebarKeyboardDndEnabled,
    setSidebarKeyboardDndEnabled,
    hideTemplates,
    setHideTemplates,
    navbarTop,
    setNavbarTop,
  } = useSettings();

  const { locale, setLocale } = useLocale();
  const [searchQuery, setSearchQuery] = useState('');

  const { enabledPanels, enablePanel, disablePanel } = usePanelList();

  const changePanelPref = (panel: Panel) => (state: boolean) => {
    if (state) {
      enablePanel(panel);
    } else {
      disablePanel(panel);
    }
  };

  const searchContext = useMemo(
    () => ({ query: searchQuery, parentMatched: false }),
    [searchQuery],
  );

  return (
    <Main>
      <ContainerNarrow>
        <h1>Settings</h1>
        <SettingsSearchWrapper hasPrefix>
          <FaMagnifyingGlass />
          <InputStyled
            type='text'
            placeholder='Search settings...'
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <ClearButton
              type='button'
              onClick={() => setSearchQuery('')}
              title='Clear search'
            >
              <FaXmark />
            </ClearButton>
          )}
        </SettingsSearchWrapper>
        <SettingsSearchProvider value={searchContext}>
          <SettingsGroup>
            <SettingsSection label='Language'>
              <BasicSelect
                value={locale}
                onChange={e => setLocale(e.target.value)}
              >
                {SUPPORTED_LOCALES.map(locale_code => (
                  <option key={locale_code} value={locale_code}>
                    {getLocaleName(locale_code)}
                  </option>
                ))}
              </BasicSelect>
            </SettingsSection>
            <SettingsSection label='Appearance'>
              <Column gap='1rem'>
                <Column gap='0.5rem'>
                  <SubLabel>Theme</SubLabel>
                  <Row>
                    <Button
                      subtle={!(darkModeSetting === DarkModeOption.auto)}
                      onClick={() => setDarkMode(undefined)}
                      title="Use the browser's / OS dark mode settings"
                    >
                      Auto
                    </Button>
                    <Button
                      subtle={!(darkModeSetting === DarkModeOption.always)}
                      onClick={() => setDarkMode(true)}
                    >
                      Dark
                    </Button>
                    <Button
                      subtle={!(darkModeSetting === DarkModeOption.never)}
                      onClick={() => setDarkMode(false)}
                    >
                      Light
                    </Button>
                  </Row>
                </Column>
                <Column gap='0.5rem'>
                  <SubLabel>NavBar position</SubLabel>
                  <Row>
                    <Button
                      subtle={!navbarTop}
                      onClick={() => setNavbarTop(true)}
                    >
                      Top
                    </Button>
                    <Button
                      subtle={navbarTop}
                      onClick={() => setNavbarTop(false)}
                    >
                      Bottom
                    </Button>
                  </Row>
                </Column>
                <Column gap='0.5rem'>
                  <SubLabel>Main color</SubLabel>
                  <MainColorPicker />
                </Column>
                <CheckboxLabel>
                  <Checkbox checked={colorfulMode} onChange={setColorfulMode} />{' '}
                  <span>Colorful mode</span>
                </CheckboxLabel>
              </Column>
            </SettingsSection>
            <SettingsSection label='Panels & Templates'>
              <Column gap='0.5rem'>
                <CheckboxLabel>
                  <Checkbox
                    checked={enabledPanels.has(Panel.Ontologies)}
                    onChange={changePanelPref(Panel.Ontologies)}
                  />{' '}
                  <span>Enable Ontology panel</span>
                </CheckboxLabel>
                <CheckboxLabel>
                  <Checkbox
                    checked={enabledPanels.has(Panel.AIChats)}
                    onChange={changePanelPref(Panel.AIChats)}
                  />{' '}
                  <span>Enable AIChats panel</span>
                </CheckboxLabel>
                <CheckboxLabel>
                  <Checkbox
                    checked={hideTemplates}
                    onChange={setHideTemplates}
                  />{' '}
                  <span>Hide templates on new resource page</span>
                </CheckboxLabel>
              </Column>
            </SettingsSection>
            <SettingsSection
              label='Accessibility'
              childSearchKeywords='disable page transition animations view transitions motion'
            >
              <Column gap='0.5rem'>
                <CheckboxLabel>
                  <Checkbox
                    checked={viewTransitionsDisabled}
                    onChange={checked => setViewTransitionsDisabled(checked)}
                  />{' '}
                  <span>Disable page transition animations</span>
                </CheckboxLabel>
                <CheckboxLabel>
                  <Checkbox
                    checked={sidebarKeyboardDndEnabled}
                    onChange={checked => setSidebarKeyboardDndEnabled(checked)}
                  />{' '}
                  <span>Enable keyboard drag & drop in sidebar</span>
                </CheckboxLabel>
              </Column>
            </SettingsSection>
            {isVirtualDriveAvailable() && (
              <SettingsSection label='Virtual drive'>
                <VirtualDriveSettings />
              </SettingsSection>
            )}
            <AISettings />
          </SettingsGroup>
        </SettingsSearchProvider>
      </ContainerNarrow>
    </Main>
  );
};

const MainColorPicker = () => {
  const { mainColor, setMainColor } = useSettings();
  const [customizing, setCustomizing] = useState(
    () => !presetColors.includes(mainColor),
  );

  return (
    <Column gap='0.5rem'>
      <SwatchRow>
        {presetColors.map(color => (
          <ColorSwatch
            key={color}
            type='button'
            color={color}
            title={color}
            $selected={!customizing && mainColor === color}
            onClick={() => {
              setMainColor(color);
              setCustomizing(false);
            }}
          />
        ))}
        <CustomizeButton
          type='button'
          $selected={customizing}
          onClick={() => setCustomizing(prev => !prev)}
        >
          Customize
        </CustomizeButton>
      </SwatchRow>
      {customizing && (
        <HexColorPicker color={mainColor} onChange={val => setMainColor(val)} />
      )}
    </Column>
  );
};

const SwatchRow = styled(Row)`
  flex-wrap: wrap;
  gap: 0.5rem;
`;

const ColorSwatch = styled.button<{ color: string; $selected: boolean }>`
  background-color: ${p => p.color};
  border: none;
  height: 1.75rem;
  width: 1.75rem;
  border-radius: ${p => p.theme.radius};
  cursor: pointer;
  outline: 2px solid transparent;
  outline-offset: 2px;
  ${p => p.$selected && `outline-color: ${p.theme.colors.textLight};`}
  &:hover,
  &:focus-visible {
    outline-color: ${p => p.theme.colors.textLight};
  }
`;

const CustomizeButton = styled.button<{ $selected: boolean }>`
  height: 1.75rem;
  padding-inline: 0.6rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};
  background-color: ${p =>
    p.$selected ? p.theme.colors.bg1 : p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  font-size: 0.8rem;
  cursor: pointer;
  &:hover,
  &:focus-visible {
    border-color: ${p => p.theme.colors.textLight};
  }
`;

const SettingsSearchWrapper = styled(InputWrapper)`
  margin-block: ${p => p.theme.margin}rem;
`;

const ClearButton = styled.button`
  display: flex;
  align-items: center;
  justify-content: center;
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.4rem;
  color: ${p => p.theme.colors.textLight};
  &:hover {
    color: ${p => p.theme.colors.text};
  }
`;

const SubLabel = styled.span`
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;
