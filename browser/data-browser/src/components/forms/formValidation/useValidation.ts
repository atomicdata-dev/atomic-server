import { useCallback, useContext, useId, useState } from 'react';
import { FormValidationContext } from './FormValidationContextProvider';
import { useLifecycleWithDependencies } from './useLifecycleWithDependencies';

export function useValidation(
  initialValue?: string | undefined,
): [
  error: string | undefined,
  setError: (error: string | undefined) => void,
  onBlur: () => void,
] {
  const id = useId();

  const [touched, setTouched] = useState(false);
  const { setValidations, validations } = useContext(FormValidationContext);

  const setError = useCallback((error: string | undefined) => {
    setValidations(prev => {
      if (prev[id] === error) {
        return prev;
      }

      return {
        ...prev,
        [id]: error,
      };
    });
  }, []);

  const handleBlur = useCallback(() => {
    setTouched(true);
  }, []);

  useLifecycleWithDependencies(
    () => {
      setValidations(prev => {
        return {
          ...prev,
          [id]: initialValue,
        };
      });
    },
    () => {
      setValidations(prev => {
        const { [id]: _, ...rest } = prev;

        return rest;
      });
    },
  );

  const error = touched ? validations[id] : undefined;

  return [error, setError, handleBlur];
}
