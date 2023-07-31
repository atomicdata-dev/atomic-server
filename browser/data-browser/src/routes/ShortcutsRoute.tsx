import * as React from 'react';
import styled from 'styled-components';
import { ContainerNarrow } from '../components/Containers';
import { shortcuts } from '../components/HotKeyWrapper';
import { Shortcut } from '../components/Shortcut';
import { Main } from '../components/Main';

/** List of all the keyboard shorcuts */
export const Shortcuts: React.FunctionComponent = () => {
  return (
    <Main>
      <ContainerNarrow>
        <h1>Keyboard shortcuts</h1>
        <h3>Global</h3>
        <p>
          <Key shortcut={shortcuts.search} /> Search
        </p>
        <p>
          <Key shortcut={shortcuts.sidebarToggle} /> Show or hide the sidebar
        </p>
        <p>
          <Key shortcut='?' /> Show these keyboard shortcuts
        </p>
        <p>
          <Key shortcut={shortcuts.edit} /> <b>E</b>dit resource
        </p>
        <p>
          <Key shortcut={shortcuts.data} /> Show <b>d</b>ata for resource
        </p>
        <p>
          <Key shortcut={shortcuts.home} /> Show <b>h</b>ome page
        </p>
        <p>
          <Key shortcut={shortcuts.new} /> <b>N</b>ew resource
        </p>
        <p>
          <Key shortcut={shortcuts.menu} /> Open <b>m</b>enu
        </p>
        <p>
          <Key shortcut={shortcuts.userSettings} /> <b>U</b>ser settings
        </p>
        <p>
          <Key shortcut={shortcuts.themeSettings} /> <b>T</b>heme settings
        </p>
        <h3>Document</h3>
        <p>
          <Key shortcut={shortcuts.moveLineUp} /> Move line / section up
        </p>
        <p>
          <Key shortcut={shortcuts.moveLineDown} /> Move line / section down
        </p>
        <p>
          <Key shortcut={shortcuts.deleteLine} /> Delete line
        </p>
      </ContainerNarrow>
    </Main>
  );
};

const Key = styled(Shortcut)`
  font-size: 1rem;
`;
