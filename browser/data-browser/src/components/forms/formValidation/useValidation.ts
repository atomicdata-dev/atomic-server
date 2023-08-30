import { useCallback, useContext, useId, useState } from 'react';
import { FormValidationContext } from './FormValidationContextProvider';
import { useLifecycleWithDependencies } from './useLifecycleWithDependencies';

export function useValidation(
  initialValue?: string | undefined,
): [
  error: string | undefined,
  setError: (error: Error | string | undefined, immediate?: boolean) => void,
  onBlur: () => void,
] {
  const id = useId();

  const [touched, setTouched] = useState(false);
  const { setValidations, validations } = useContext(FormValidationContext);

  const setError = useCallback(
    (error: Error | string | undefined, immediate = false) => {
      const err = error instanceof Error ? error.message : error;

      setValidations(prev => {
        if (prev[id] === err) {
          return prev;
        }

        return {
          ...prev,
          [id]: err,
        };
      });

      if (immediate) {
        setTouched(true);
      }
    },
    [],
  );

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
