import {
  createContext,
  PropsWithChildren,
  useCallback,
  useEffect,
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
      _setValidations(prev => update(prev));
    },
    [onValidationChange],
  );

  const context = useMemo(
    () => ({
      validations,
      setValidations,
    }),
    [validations, setValidations],
  );

  useEffect(() => {
    onValidationChange(Object.values(validations).every(v => v === undefined));
  }, [validations, onValidationChange]);

  return (
    <FormValidationContext.Provider value={context}>
      {children}
    </FormValidationContext.Provider>
  );
}
