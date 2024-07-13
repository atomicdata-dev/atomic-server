import { Route, Routes } from 'react-router-dom';
import { ViewIndex } from './ViewIndex';
import { ViewProgram } from './ViewProgram';

const fixURL = function (url: string): string {
  return url.replace('5173', '9883');
}

export function AppRoutes(): JSX.Element {
  return (
    <Routes>
      <Route path='/ohjelmat?' element={<ViewIndex />} />
      <Route path='/*' element={<ViewProgram subject={fixURL(window.location.href)} />} />
    </Routes>
  );
}

export default AppRoutes;
