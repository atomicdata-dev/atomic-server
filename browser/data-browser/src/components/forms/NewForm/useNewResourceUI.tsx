import { Core, Store, useStore } from '@tomic/react';
import {
  FC,
  PropsWithChildren,
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from 'react';
import {
  useCreateAndNavigate,
  CreateAndNavigate,
} from '../../../hooks/useCreateAndNavigate';
import { AppSettings, useSettings } from '../../../helpers/AppSettings';
import { newURL } from '../../../helpers/navigation';
import { useNavigateWithTransition } from '../../../hooks/useNavigateWithTransition';

export interface CustomResourceDialogProps {
  parent: string;
  onClose: () => void;
}

/**  When creating a new resource, the matched handler is called */
export type BasicInstanceHandler = (
  parent: string,
  createAndNavigate: CreateAndNavigate,
  context: {
    store: Store;
    settings: AppSettings;
  },
) => Promise<void>;

interface NewResourceUIContext {
  showNewResourceUI: (classType: string, parent: string) => void;
}

const dialogs = new Map<string, FC<CustomResourceDialogProps>>();
const basicNewInstanceHandlers = new Map<string, BasicInstanceHandler>();

/**
 * Returns a function that when called, renders UI to create a new Resource of the given class.
 *
 * Use {@link registerNewResourceDialog} to register a custom dialog for a given class.
 */
export function useNewResourceUI() {
  const { showNewResourceUI } = useContext(NewResourceUIContext);

  return showNewResourceUI;
}

/** Call this when adding a new custom New Resource Form / Dialog. */
export const registerNewResourceDialog = (
  classSubject: string,
  component: FC<CustomResourceDialogProps>,
) => {
  dialogs.set(classSubject, component);
};

/** Call this when adding a new custom action for a New Resource that does _not_ require inputs.
 * For example, creating a new Folder does not require any inputs, so it can be handled without any UI.
 */
export const registerBasicInstanceHandler = (
  classSubject: string,
  handler: BasicInstanceHandler,
) => {
  basicNewInstanceHandlers.set(classSubject, handler);
};

const NewResourceUIContext = createContext<NewResourceUIContext>({
  showNewResourceUI: () => undefined,
});

/** Renders the Dialog used when creating new resources. */
export function NewResourceUIProvider({ children }: PropsWithChildren) {
  const store = useStore();
  const settings = useSettings();
  const createAndNavigate = useCreateAndNavigate();
  const [Dialog, setDialog] = useState<JSX.Element | undefined>(undefined);
  const navigate = useNavigateWithTransition();

  const showNewResourceUI = useCallback(async (isA: string, parent: string) => {
    // Show a dialog if one is registered for the given class
    if (dialogs.has(isA)) {
      const onClose = () => {
        setDialog(undefined);
      };

      const Comp = dialogs.get(isA)!;
      setDialog(<Comp parent={parent} onClose={onClose} />);

      return;
    }

    // If a basicInstanceHandler is registered for the class, create a resource of the given class with some default values.
    if (basicNewInstanceHandlers.has(isA)) {
      try {
        await basicNewInstanceHandlers.get(isA)?.(parent, createAndNavigate, {
          store,
          settings,
        });
      } catch (e) {
        store.notifyError(e);
      }

      return;
    }

    // Default behaviour. Navigate to a new resource form for the given class.
    const classResource = await store.getResourceAsync<Core.Class>(isA);
    navigate(
      newURL(isA, parent, store.createSubject(classResource.props.shortname)),
    );
  }, []);

  const context = useMemo(
    () => ({
      showNewResourceUI,
    }),
    [showNewResourceUI],
  );

  return (
    <NewResourceUIContext.Provider value={context}>
      {children}
      {Dialog}
    </NewResourceUIContext.Provider>
  );
}
