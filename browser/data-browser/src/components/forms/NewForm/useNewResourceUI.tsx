import { core, dataBrowser } from '@tomic/react';
import {
  FC,
  PropsWithChildren,
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from 'react';
import { NewTableDialog } from './CustomForms/NewTableDialog';
import { NewOntologyDialog } from './CustomForms/NewOntologyDialog';
import { NewBookmarkDialog } from './CustomForms/NewBookmarkDialog';

export interface CustomResourceDialogProps {
  parent: string;
  onClose: () => void;
}

export function useNewResourceUI() {
  const { showNewResourceUI } = useContext(NewResourceUIContext);

  return showNewResourceUI;
}

const dialogs = new Map<string, FC<CustomResourceDialogProps>>([
  [core.classes.ontology, NewOntologyDialog],
  [dataBrowser.classes.table, NewTableDialog],
  [dataBrowser.classes.bookmark, NewBookmarkDialog],
]);

interface NewResourceUIContext {
  showNewResourceUI: (classType: string, parent: string) => void;
}

const NewResourceUIContext = createContext<NewResourceUIContext>({
  showNewResourceUI: () => undefined,
});

export function NewResourceUIProvider({ children }: PropsWithChildren) {
  const [Dialog, setDialog] = useState<JSX.Element | undefined>(undefined);

  const showNewResourceUI = useCallback((classType: string, parent: string) => {
    if (!dialogs.has(classType)) {
      // TODO: Default behaviour
      return;
    }

    const onClose = () => {
      setDialog(undefined);
    };

    const Comp = dialogs.get(classType)!;
    setDialog(<Comp parent={parent} onClose={onClose} />);
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
