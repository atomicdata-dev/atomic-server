import {
  createContext,
  Dispatch,
  FC,
  PropsWithChildren,
  SetStateAction,
  useContext,
  useMemo,
  useState,
} from 'react';

interface DialogTreeContext {
  inDialog: boolean;
  hasOpenInnerPopup: boolean;
  setHasOpenInnerPopup: Dispatch<SetStateAction<boolean>>;
}

export const DialogTreeContext = createContext<DialogTreeContext>({
  inDialog: false,
  hasOpenInnerPopup: false,
  setHasOpenInnerPopup: () => undefined,
});

export const DialogTreeContextProvider: FC<PropsWithChildren> = ({
  children,
}) => {
  // Keep track of whether there is an open inner popup. This can be used to disable dismissal controls in dialogs while a popup is open.
  const [hasOpenInnerPopup, setHasOpenInnerPopup] = useState<boolean>(false);

  const context = useMemo(
    () => ({
      inDialog: true,
      hasOpenInnerPopup,
      setHasOpenInnerPopup,
    }),
    [hasOpenInnerPopup, setHasOpenInnerPopup],
  );

  return (
    <DialogTreeContext.Provider value={context}>
      {children}
    </DialogTreeContext.Provider>
  );
};

export function useDialogTreeInfo() {
  const { inDialog, hasOpenInnerPopup, setHasOpenInnerPopup } =
    useContext(DialogTreeContext);

  return {
    inDialog,
    hasOpenInnerPopup,
    setHasOpenInnerPopup,
  };
}

export function useDialogTreeContext() {
  return useContext(DialogTreeContext);
}
