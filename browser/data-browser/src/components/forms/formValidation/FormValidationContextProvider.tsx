import {
  createContext,
  PropsWithChildren,
  useCallback,
  useMemo,
  useState,
} from 'react';

type Validations = Record<string, string | undefined>;

export interface FormValidationContextProps {
  validations: Validations;
  setValidations: (
    update: (newValidations: Validations) => Validations,
  ) => void;
}

export const FormValidationContext = createContext<FormValidationContextProps>({
  validations: {},
  setValidations: () => undefined,
});

export type FormValidationContextProviderProps = PropsWithChildren<{
  onValidationChange: (valid: boolean) => void;
}>;
export function FormValidationContextProvider({
  children,
  onValidationChange,
}: FormValidationContextProviderProps) {
  const [validations, _setValidations] = useState<Validations>({});

  const setValidations = useCallback(
    (update: (newValidations: Validations) => Validations) => {
      _setValidations(prev => {
        const updatedValidations = update(prev);

        onValidationChange(
          Object.values(updatedValidations).every(v => v === undefined),
        );

        return updatedValidations;
      });
    },
    [onValidationChange],
  );

  const context = useMemo(
    () => ({
      validations,
      setValidations,
    }),
    [validations],
  );

  return (
    <FormValidationContext.Provider value={context}>
      {children}
    </FormValidationContext.Provider>
  );
}
