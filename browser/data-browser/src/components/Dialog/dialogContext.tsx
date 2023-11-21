import {
  createContext,
  Dispatch,
  FC,
  PropsWithChildren,
  RefObject,
  SetStateAction,
  useContext,
  useMemo,
  useState,
} from 'react';

export const DialogPortalContext = createContext<RefObject<HTMLDivElement>>(
  null!,
);

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
  const [hasOpenInnerPopup, setHasOpenInnerPopup] = useState<boolean>(false);

  const context = useMemo(
    () => ({
      inDialog: true,
      hasOpenInnerPopup,
      setHasOpenInnerPopup,
    }),
    [hasOpenInnerPopup],
  );

  return (
    <DialogTreeContext.Provider value={context}>
      {children}
    </DialogTreeContext.Provider>
  );
};

export function useDialogTreeContext() {
  return useContext(DialogTreeContext);
}
