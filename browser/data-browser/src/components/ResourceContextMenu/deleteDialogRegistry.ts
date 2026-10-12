import type { FC } from 'react';
import type { Resource } from '@tomic/react';

export interface DeleteDialogProps {
  resource: Resource;
  show: boolean;
  bindShow: (show: boolean) => void;
  /**
   * Call once the resource (and anything it cascaded) has been destroyed.
   * Runs the shared post-delete side effects (toast, navigate away if this
   * was the open page, `onAfterDelete`). `parent` is the subject to
   * navigate back to, read before destroying.
   */
  onDeleted: (parent: string | undefined) => void;
}

const deleteDialogs = new Map<string, FC<DeleteDialogProps>>();

/**
 * Register a custom delete-confirmation dialog for a class of resources.
 * Resources without a registered class fall back to the generic dialog.
 */
export const registerDeleteDialog = (
  classSubject: string,
  component: FC<DeleteDialogProps>,
) => {
  deleteDialogs.set(classSubject, component);
};

export const getDeleteDialog = (
  classSubject: string | undefined,
): FC<DeleteDialogProps> | undefined =>
  classSubject ? deleteDialogs.get(classSubject) : undefined;
