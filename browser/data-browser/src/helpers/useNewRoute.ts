import { useCallback } from 'react';
import { useNavigate } from 'react-router';
import { paths } from '../routes/paths';

function buildURL(parent?: string) {
  const params = new URLSearchParams({
    ...(parent ? { parentSubject: parent } : {}),
  });

  return `${paths.new}?${params.toString()}`;
}

export function useNewRoute(parent?: string) {
  const navigate = useNavigate();

  const navigateToNewRoute = useCallback(() => {
    const url = buildURL(parent);
    navigate(url);
  }, [parent]);

  return navigateToNewRoute;
}
