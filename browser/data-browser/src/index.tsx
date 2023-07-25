import React from 'react';
import { createRoot } from 'react-dom/client';

import App from './App';

/**
 * Top level React node of the Application. Keep this one empty (no providers),
 * as the Testing library imports the App component
 */
const root = createRoot(document.getElementById('root')!);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
