/// <reference types="vite/client" />

import { Route, Routes } from 'react-router-dom';

import Show from './ShowRoute';
import { Search } from './SearchRoute';
import NewRoute from './NewResource/NewRoute';
import { SettingsTheme } from './SettingsTheme';
import { Edit } from './EditRoute';
import Data from './DataRoute';
import { Shortcuts } from './ShortcutsRoute';
import { About as About } from './AboutRoute';
import Local from './LocalRoute';
import { SettingsAgentRoute } from './SettingsAgent';
import { SettingsServer } from './SettingsServer';
import { paths } from './paths';
import ResourcePage from '../views/ResourcePage';
import { ShareRoute } from './Share/ShareRoute';
import { Sandbox } from './Sandbox';
import { TokenRoute } from './TokenRoute';
import { ImporterPage } from '../views/ImporterPage';
import { History } from './History';
import { PruneTestsRoute } from './PruneTestsRoute';
import ConfirmEmail from './ConfirmEmail';

/** Server URLs should have a `/` at the end */
const homeURL = window.location.origin + '/';

const isDev = import.meta.env.MODE === 'development';

/**
 * Handles the browser URL navigation paths. Some rules:
 *
 * - Resource defined by this app should start with `/app`
 * - The home page should show the atomic data resource of the same URL
 */
export function AppRoutes(): JSX.Element {
  return (
    <Routes>
      <Route path={paths.new} element={<NewRoute />} />
      <Route path={paths.themeSettings} element={<SettingsTheme />} />
      <Route path={paths.agentSettings} element={<SettingsAgentRoute />} />
      <Route path={paths.serverSettings} element={<SettingsServer />} />
      <Route path={paths.shortcuts} element={<Shortcuts />} />
      <Route path={paths.data} element={<Data />} />
      <Route path={paths.edit} element={<Edit />} />
      <Route path={paths.import} element={<ImporterPage />} />
      <Route path={paths.share} element={<ShareRoute />} />
      <Route path={paths.show} element={<Show />} />
      <Route path={paths.about} element={<About />} />
      <Route path={paths.search} element={<Search />} />
      <Route path={paths.token} element={<TokenRoute />} />
      <Route path={paths.history} element={<History />} />
      {isDev && <Route path={paths.pruneTests} element={<PruneTestsRoute />} />}
      {isDev && <Route path={paths.sandbox} element={<Sandbox />} />}
      <Route path={paths.confirmEmail} element={<ConfirmEmail />} />
      <Route path='/' element={<ResourcePage subject={homeURL} />} />
      <Route path='*' element={<Local />} />
    </Routes>
  );
}
