import React, { createContext, useMemo, useState } from 'react';

export const DialogPortalContext = createContext<
  React.RefObject<HTMLDivElement>
>(null!);

interface DialogTreeContext {
  inDialog: boolean;
  hasOpenInnerPopup: boolean;
  setHasOpenInnerPopup: React.Dispatch<React.SetStateAction<boolean>>;
}

export const DialogTreeContext = createContext<DialogTreeContext>({
  inDialog: false,
  hasOpenInnerPopup: false,
  setHasOpenInnerPopup: () => undefined,
});

export const DialogTreeContextProvider: React.FC<React.PropsWithChildren> = ({
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
  return React.useContext(DialogTreeContext);
}
