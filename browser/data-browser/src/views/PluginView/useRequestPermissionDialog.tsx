import React, { useState, useRef, useEffect } from 'react';
import { Dialog, useDialog } from '@components/Dialog';
import { Column } from '@components/Row';
import { Checkbox, CheckboxLabel } from '@components/forms/Checkbox';
import { ResourceInline } from '@views/ResourceInline';
import { Button } from '@components/Button';

import { useStoredPluginGrants } from './useStoredPluginGrants';

export type RequestPermissionFn = (subject: string) => Promise<boolean>;

/**
 * Returns a function to ask the user for permissions for a resource. If the plugin was already given permission it will resolve to true.
 */
// Due to the way React works we need a lot of refs to keep a consistent queueing behavior for all the popups.
export function useRequestPermissionDialog(
  plugin: string,
  type: 'read' | 'write',
  installation: string,
): [RequestPermissionFn, React.ReactNode, (subject: string) => boolean] {
  const [show, setShow] = useState(false);
  const [requestedSubject, setRequestedSubject] = useState<string | undefined>(
    undefined,
  );
  // Track the 'allow all' checkbox state here to easily reset it between requests
  const [allowAll, setAllowAll] = useState(false);

  const { grants: permissions, setGrants: setPermissions } =
    useStoredPluginGrants(installation, type);

  // Keep a ref to permissions to access the latest value in the queue processing logic
  const permissionsRef = useRef(permissions);
  useEffect(() => {
    permissionsRef.current = permissions;
  }, [permissions]);

  const queueRef = useRef<{ subject: string; resolve: (v: boolean) => void }[]>(
    [],
  );
  const resolverRef = useRef<((value: boolean) => void) | undefined>(undefined);

  useEffect(
    () => () => {
      resolverRef.current?.(false);
      resolverRef.current = undefined;
      for (const request of queueRef.current.splice(0)) request.resolve(false);
    },
    [],
  );

  const processQueue = () => {
    if (resolverRef.current) {
      // Already processing a request
      return;
    }

    // Process the queue iteratively to avoid recursion linter errors
    // and skip already allowed subjects
    while (true) {
      const next = queueRef.current.shift();

      if (!next) {
        setRequestedSubject(undefined);
        setShow(false);

        return;
      }

      // Check if the subject is already allowed
      if (
        permissionsRef.current.allowAll ||
        permissionsRef.current.allowed.includes(next.subject)
      ) {
        next.resolve(true);
        continue;
      }

      setRequestedSubject(next.subject);
      setAllowAll(false); // Reset checkbox for each new request
      resolverRef.current = next.resolve;
      setShow(true);
      break;
    }
  };

  const requestPermission = (subject: string): Promise<boolean> => {
    // Immediate check before queuing
    if (
      permissionsRef.current.allowAll ||
      permissionsRef.current.allowed.includes(subject)
    ) {
      return Promise.resolve(true);
    }

    return new Promise<boolean>(resolve => {
      queueRef.current.push({ subject, resolve });
      processQueue();
    });
  };

  const handleGrantResult = (grantResult: ScopeGrantResult) => {
    let nextPermissions = permissionsRef.current;

    if (grantResult.allowAll) {
      nextPermissions = {
        ...nextPermissions,
        allowAll: true,
        allowed: [],
      };
      setPermissions(nextPermissions);
      permissionsRef.current = nextPermissions;

      // Resolve all pending requests in the queue as true
      queueRef.current.forEach(item => item.resolve(true));
      queueRef.current = [];
    } else if (grantResult.allowed) {
      nextPermissions = {
        ...nextPermissions,
        allowAll: false,
        allowed: [...nextPermissions.allowed, grantResult.subject],
      };
      setPermissions(nextPermissions);
      permissionsRef.current = nextPermissions;
    }

    const resolve = resolverRef.current;
    resolverRef.current = undefined;
    resolve?.(grantResult.allowed);

    // Move to the next request in the queue
    processQueue();
  };

  const dialog = (
    <RequestPermissionDialog
      plugin={plugin}
      show={show}
      subject={requestedSubject}
      allowAll={allowAll}
      setAllowAll={setAllowAll}
      onResult={handleGrantResult}
      bindShow={setShow}
      type={type}
    />
  );

  return [
    requestPermission,
    dialog,
    subject =>
      permissionsRef.current.allowAll ||
      permissionsRef.current.allowed.includes(subject),
  ];
}

interface ScopeGrantResult {
  subject: string;
  allowed: boolean;
  allowAll: boolean;
}

interface RequestPermissionDialogProps {
  plugin: string;
  subject?: string;
  onResult: (result: ScopeGrantResult) => void;
  show: boolean;
  bindShow: (show: boolean) => void;
  allowAll: boolean;
  setAllowAll: (allowAll: boolean) => void;
  type: 'read' | 'write';
}

const RequestPermissionDialog = ({
  plugin,
  subject,
  onResult,
  show,
  bindShow,
  allowAll,
  setAllowAll,
  type,
}: RequestPermissionDialogProps) => {
  const [dialogProps, showDialog, closeDialog] = useDialog({
    bindShow,
    onCancel: () =>
      onResult({ subject: subject!, allowed: false, allowAll: false }),
    onSuccess: () => onResult({ subject: subject!, allowed: true, allowAll }),
  });

  useEffect(() => {
    if (show) {
      showDialog();
    }
  }, [show, showDialog, subject]);

  const title = type === 'read' ? 'Read Request' : 'Write Request';
  const checkboxLabel =
    type === 'read'
      ? 'Allow all reads done by this plugin'
      : 'Allow all writes done by this plugin';

  return (
    <Dialog {...dialogProps}>
      <Dialog.Title>
        <h1>{title}</h1>
      </Dialog.Title>
      <Dialog.Content>
        <Column>
          {type === 'read' ? (
            <p>
              <strong>{plugin}</strong> wants to read a resource that is not
              contained in the current scope.
            </p>
          ) : (
            <p>
              <strong>{plugin}</strong> wants to modify a resource that is not
              contained in the current scope.
            </p>
          )}
          {subject && <ResourceInline subject={subject} />}
          <CheckboxLabel>
            <Checkbox checked={allowAll} onChange={setAllowAll} />
            {checkboxLabel}
          </CheckboxLabel>
        </Column>
      </Dialog.Content>
      <Dialog.Actions>
        <Button subtle onClick={() => closeDialog(false)}>
          Deny
        </Button>
        <Button onClick={() => closeDialog(true)}>Allow</Button>
      </Dialog.Actions>
    </Dialog>
  );
};
