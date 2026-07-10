import toast from 'react-hot-toast';
import { useCallback } from 'react';
import { constructOpenURL } from '../helpers/navigation';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { useNavigateWithTransition } from './useNavigateWithTransition';

/**
 * Shared post-delete side effects: toast, navigate back to the parent only
 * if the deleted resource was the currently open page, and notify the
 * caller. Used by the generic delete flow and by class-specific delete
 * dialogs registered in `deleteDialogRegistry` so navigation stays correct
 * regardless of where the delete was triggered from (e.g. the sidebar,
 * deleting a resource that isn't the open page, must not navigate away).
 */
export function useAfterResourceDelete(
  subject: string,
  onAfterDelete?: () => void,
) {
  const navigate = useNavigateWithTransition();
  const [currentSubject] = useCurrentSubject();

  return useCallback(
    (parent: string | undefined) => {
      onAfterDelete?.();
      toast.success('Resource deleted!');

      if (currentSubject === subject) {
        navigate(parent ? constructOpenURL(parent) : '/');
      }
    },
    [subject, currentSubject, navigate, onAfterDelete],
  );
}
