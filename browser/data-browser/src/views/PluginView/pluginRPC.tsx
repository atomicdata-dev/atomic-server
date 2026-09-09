import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { useCurrentAgent, useResource, useStore } from '@tomic/react';
import React, { useEffect, useRef } from 'react';
import { useCurrentSubject } from '@helpers/useCurrentSubject';
import { constructOpenURL } from '@helpers/navigation';
import { useResourcePicker } from './useResourcePicker';
import { useFilePicker } from './useFilePicker';
import type { UIPluginData } from '@components/CustomViewProvider';
import { useRequestPermissionDialog } from './useRequestPermissionDialog';
import {
  LegacyViewAdapter,
  resourceToUIPluginResource,
} from './legacyViewAdapter';

export function usePluginRPC(
  pluginData: UIPluginData,
  css: string,
): [React.RefObject<HTMLIFrameElement | null>, React.ReactNode] {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [agent] = useCurrentAgent();
  const [currentSubject] = useCurrentSubject();
  const frameRef = useRef<HTMLIFrameElement>(null);
  const pluginResource = useResource(pluginData.resource);
  const currentResource = useResource(currentSubject);

  const [
    requestReadPermission,
    requestReadPermissionDialog,
    hasReadPermission,
  ] = useRequestPermissionDialog(
    pluginData.plugin,
    'read',
    pluginData.resource,
  );
  const [requestWritePermission, requestWritePermissionDialog] =
    useRequestPermissionDialog(pluginData.plugin, 'write', pluginData.resource);
  const [pickResource, resourcePickerDialog] = useResourcePicker(
    pluginData.resource,
  );
  const [pickFile, filePickerDialog] = useFilePicker();

  const serverRef = useRef<LegacyViewAdapter | undefined>(undefined);

  const latest = useRef({
    currentResource,
    pluginResource,
    navigate,
    pickResource,
    pickFile,
    requestReadPermission,
    requestWritePermission,
    hasReadPermission,
  });
  latest.current = {
    currentResource,
    pluginResource,
    navigate,
    pickResource,
    pickFile,
    requestReadPermission,
    requestWritePermission,
    hasReadPermission,
  };

  useEffect(() => {
    if (!frameRef.current) return;
    const adapter = new LegacyViewAdapter({
      context: {
        resource: resourceToUIPluginResource(
          latest.current.currentResource.stable,
        ),
        agent: agent?.subject ?? '',
      },
      store,
      iFrame: frameRef.current,
      pluginResource: latest.current.pluginResource.stable,
      navigate: subject => latest.current.navigate(constructOpenURL(subject)),
      pickResource: args => latest.current.pickResource(args),
      pickFile: args => latest.current.pickFile(args),
      requestReadPermission: subject =>
        latest.current.requestReadPermission(subject),
      hasReadPermission: subject => latest.current.hasReadPermission(subject),
      requestWritePermission: subject =>
        latest.current.requestWritePermission(subject),
    });
    serverRef.current = adapter;

    return () => {
      adapter.stopServer();
      serverRef.current = undefined;
    };
  }, [store, currentSubject, pluginData.resource, agent?.subject]);

  useEffect(() => {
    if (!serverRef.current) return;
    serverRef.current.context = {
      resource: resourceToUIPluginResource(currentResource.stable),
      agent: agent?.subject ?? '',
    };
    serverRef.current.pluginResource = pluginResource.stable;
    serverRef.current.setStyle(css);
  });

  return [
    frameRef,
    <>
      {resourcePickerDialog}
      {filePickerDialog}
      {requestReadPermissionDialog}
      {requestWritePermissionDialog}
    </>,
  ];
}
