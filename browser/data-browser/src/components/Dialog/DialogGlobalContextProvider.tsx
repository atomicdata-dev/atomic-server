import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type FC,
  type PropsWithChildren,
  type RefObject,
} from 'react';
import { styled } from 'styled-components';

interface DialogGlobalContext {
  openDialogs: string[];
  setDialogOpen: (id: string, open: boolean) => void;
  portal: RefObject<HTMLDivElement>;
}

export const DialogContext = createContext<DialogGlobalContext>(null!);

export const DialogGlobalContextProvider: FC<PropsWithChildren> = ({
  children,
}) => {
  const [openDialogs, setOpenDialogs] = useState<string[]>([]);
  const portalRef = useRef<HTMLDivElement>(null);

  const setDialogOpen = useCallback((id: string, open: boolean) => {
    if (open) {
      setOpenDialogs(prev => {
        if (prev.includes(id)) {
          return prev;
        }

        return [...prev, id];
      });
    } else {
      setOpenDialogs(prev => prev.filter(dialogId => dialogId !== id));
    }
  }, []);

  const context = useMemo(
    () => ({ openDialogs, setDialogOpen, portal: portalRef }),
    [openDialogs, setDialogOpen, portalRef],
  );

  return (
    <DialogContext.Provider value={context}>
      {children}
      <StyledDiv ref={portalRef}></StyledDiv>
    </DialogContext.Provider>
  );
};

export function useDialogGlobalContext(open: boolean) {
  const id = useId();
  const { openDialogs, setDialogOpen, ...context } = useContext(DialogContext);

  const isTopLevel = openDialogs.at(-1) === id;

  useEffect(() => {
    setDialogOpen(id, open);
  }, [open, id]);

  return {
    isTopLevel,
    ...context,
  };
}

const StyledDiv = styled.div`
  display: contents;
`;
