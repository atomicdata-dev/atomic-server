import { useCallback } from 'react';
import { useNavigate } from 'react-router';
import { useQueryString } from '../helpers/navigation';

export interface QueryScopeHandler {
  scope: string | undefined;
  enableScope: () => void;
  clearScope: () => void;
}

export function useQueryScopeHandler(subject: string): QueryScopeHandler;
export function useQueryScopeHandler(): Omit<QueryScopeHandler, 'enableScope'>;
export function useQueryScopeHandler(subject?: string): QueryScopeHandler {
  const [scope, setScope] = useQueryString('queryscope');
  const navigate = useNavigate();

  const enableScope = useCallback(() => {
    const params = new URLSearchParams({
      queryscope: subject ?? '',
    });

    navigate(`/app/search?${params.toString()}`, { replace: true });
  }, [setScope, subject]);

  const clearScope = useCallback(() => {
    setScope(undefined);
  }, [setScope]);

  return {
    scope,
    enableScope,
    clearScope,
  };
}
