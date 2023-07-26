import React from 'react';
import { useSettings } from '../helpers/AppSettings';
import { RegisterSignIn } from './RegisterSignIn';

/**
 * The Guard can be wrapped around a Component that depends on a user being logged in.
 * If the user is not logged in, it will show a button to sign up / sign in.
 * Show to users after a new Agent has been created.
 * Instructs them to save their secret somewhere safe
 */
export function Guard({ children }: React.PropsWithChildren<any>): JSX.Element {
  const { agent } = useSettings();

  if (agent) {
    return <>{children}</>;
  } else return <RegisterSignIn />;
}
