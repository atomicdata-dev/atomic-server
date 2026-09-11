import type { SetupArguments, SetupDeclaration, Store } from '@tomic/lib';

export interface SetupContext {
  store: Store;
  drive: string;
}
export interface SetupChoice {
  value: string;
  label: string;
}
/** Bundled host adapters only. This is not a loader for arbitrary app source. */
export interface SetupAdapter {
  id: string;
  icon: string;
  declaration: SetupDeclaration;
  defaults?: (workspace?: string) => SetupArguments;
  choices: (lookup: string, context: SetupContext) => Promise<SetupChoice[]>;
  credential?: {
    label: string;
    description: string;
    link?: (args: SetupArguments) => string;
    linkLabel?: string;
  };
  preflight?: (context: SetupContext) => Promise<void>;
  prepare?: (args: SetupArguments) => SetupArguments;
  connect: (
    args: SetupArguments,
    credential: string,
    context: SetupContext,
  ) => Promise<{ subject: string }>;
}
